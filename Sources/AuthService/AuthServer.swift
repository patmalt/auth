import Foundation
import Logging
import NIOCore
import NIOHTTP1
import NIOPosix

actor AuthServer {
    private let configuration: ServiceConfiguration
    private let store: any CredentialStoring
    private let logger: Logger
    private let oidc: OIDCProvider

    init(
        configuration: ServiceConfiguration,
        store: any CredentialStoring,
        logger: Logger,
        oidc: OIDCProvider
    ) {
        self.configuration = configuration
        self.store = store
        self.logger = logger
        self.oidc = oidc
    }

    func run() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        defer {
            Task {
                try? await group.shutdownGracefully()
            }
        }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(HTTPRequestHandler(server: self, logger: self.logger, eventLoop: channel.eventLoop))
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 16)
            .childChannelOption(ChannelOptions.recvAllocator, value: AdaptiveRecvByteBufferAllocator())

        let channel = try await bootstrap.bind(host: configuration.host, port: configuration.port).get()
        logger.info(
            "Auth service listening",
            metadata: [
                "host": .string(configuration.host),
                "port": .stringConvertible(configuration.port),
                "origin": .string(configuration.origin),
                "cors_allowed_origins": .array(configuration.corsAllowedOrigins.sorted().map { .string($0) }),
                "credentials_table": .string(configuration.dynamoDBCredentialsTable),
            ]
        )
        try await channel.closeFuture.get()
    }

    func respond(to request: HTTPRequestAccumulator, context: RequestContext) async -> HTTPResponsePayload {
        do {
            let response = try await handleRequest(request, context: context)
            return applyingCORS(to: response, for: request)
        } catch let error as HTTPError {
            return applyingCORS(to: errorResponse(for: error), for: request)
        } catch {
            return applyingCORS(
                to: errorResponse(for: .internalServerError("Internal server error")),
                for: request
            )
        }
    }

    func handleRequest(_ request: HTTPRequestAccumulator, context: RequestContext) async throws -> HTTPResponsePayload {
        let requestLogger = logger.with(request: context)
        requestLogger.info("Request started", metadata: ["content_length": .stringConvertible(request.body.count)])

        if request.method != .OPTIONS, let response = await oidc.respond(to: request) { return response }

        switch (request.method, request.uri) {
        case (.OPTIONS, _):
            return try preflightResponse(for: request)
        case (.GET, "/"), (.GET, "/health"):
            return try healthResponse()
        default:
            throw HTTPError.notFound("No route for \(request.method.rawValue) \(request.uri)")
        }
    }

    private func healthResponse() throws -> HTTPResponsePayload {
        try jsonResponse(
            status: .ok,
            body: HealthResponse(
                status: "ok",
                service: "AuthService"
            )
        )
    }

    private func jsonResponse<T: Encodable>(status: HTTPResponseStatus, body: T) throws -> HTTPResponsePayload {
        let data = try JSONEncoder.apiEncoder.encode(body)
        return HTTPResponsePayload(status: status, headers: ["Content-Type": "application/json"], body: data)
    }

    private func preflightResponse(for request: HTTPRequestAccumulator) throws -> HTTPResponsePayload {
        if let origin = request.headers["Origin"].first.map(normalizedOriginString),
           !isAllowedCORSOrigin(origin) {
            throw HTTPError.forbidden("Origin \(origin) is not allowed")
        }

        return HTTPResponsePayload(status: .noContent, headers: [:], body: Data())
    }

    private func errorResponse(for error: HTTPError) -> HTTPResponsePayload {
        let payload = (try? JSONEncoder.apiEncoder.encode(ErrorEnvelope(error: error.message)))
            ?? Data("{\"error\":\"\(error.message)\"}".utf8)
        return HTTPResponsePayload(
            status: HTTPResponseStatus(statusCode: error.statusCode),
            headers: ["Content-Type": "application/json"],
            body: payload
        )
    }

    private func applyingCORS(to response: HTTPResponsePayload, for request: HTTPRequestAccumulator) -> HTTPResponsePayload {
        guard let origin = request.headers["Origin"].first.map(normalizedOriginString) else {
            return response
        }

        var headers = response.headers
        headers["Vary"] = "Origin"

        guard isAllowedCORSOrigin(origin) else {
            return HTTPResponsePayload(status: response.status, headers: headers, body: response.body)
        }

        headers["Access-Control-Allow-Origin"] = configuration.corsAllowedOrigins.contains("*") ? "*" : origin
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        headers["Access-Control-Max-Age"] = "600"
        return HTTPResponsePayload(status: response.status, headers: headers, body: response.body)
    }

    private func isAllowedCORSOrigin(_ origin: String) -> Bool {
        configuration.corsAllowedOrigins.contains("*") || configuration.corsAllowedOrigins.contains(origin)
    }
}
