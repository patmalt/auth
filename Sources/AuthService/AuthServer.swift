import Foundation
import Logging
import NIOCore
import NIOHTTP1
import NIOPosix

actor AuthServer {
    private let configuration: ServiceConfiguration
    private let store: any CredentialStoring
    private let jwtService: JWTService
    private let webAuthnVerifier: any WebAuthnVerifying
    private let logger: Logger
    private let oidc: OIDCProvider?

    init(
        configuration: ServiceConfiguration,
        store: any CredentialStoring,
        logger: Logger,
        webAuthnVerifier: any WebAuthnVerifying = WebAuthnVerifier(),
        oidc: OIDCProvider? = nil
    ) {
        self.configuration = configuration
        self.store = store
        self.jwtService = JWTService(configuration: configuration)
        self.webAuthnVerifier = webAuthnVerifier
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
                "challenges_table": .string(configuration.dynamoDBChallengesTable),
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
                to: errorResponse(for: .internalServerError("Unhandled error: \(error)")),
                for: request
            )
        }
    }

    func handleRequest(_ request: HTTPRequestAccumulator, context: RequestContext) async throws -> HTTPResponsePayload {
        let requestLogger = logger.with(request: context)
        requestLogger.info("Request started", metadata: ["content_length": .stringConvertible(request.body.count)])

        if let oidc, let response = await oidc.respond(to: request) { return response }

        switch (request.method, request.uri) {
        case (.OPTIONS, _):
            return try preflightResponse(for: request)
        case (.GET, "/"), (.GET, "/health"):
            return try healthResponse()
        case (.POST, "/register/begin"):
            return try await beginRegistration(for: request, logger: requestLogger)
        case (.POST, "/register/complete"):
            return try await completeRegistration(for: request, logger: requestLogger)
        case (.POST, "/authenticate/begin"):
            return try await beginAuthentication(for: request, logger: requestLogger)
        case (.POST, "/authenticate/complete"):
            return try await completeAuthentication(for: request, logger: requestLogger)
        case (.GET, "/me"):
            return try currentUserResponse(for: request, logger: requestLogger)
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

    private func beginRegistration(for request: HTTPRequestAccumulator, logger: Logger) async throws -> HTTPResponsePayload {
        let body = try decode(RegisterBeginRequest.self, from: request.body)
        let username = body.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else {
            throw HTTPError.badRequest("Username is required")
        }
        logger.info("Registration started", metadata: ["username": .string(username)])

        let existingCredential = try await store.credential(for: username)
        let userID = existingCredential?.userID ?? randomBytes(count: 32)
        let challenge = randomBytes(count: 32)
        try await store.saveChallenge(
            ChallengeRecord(
                challenge: challenge,
                username: username,
                userID: userID,
                kind: .registration,
                expiresAt: Date().addingTimeInterval(300)
            )
        )

        let response = RegisterBeginResponse(
            challenge: Base64URL.encode(challenge),
            rp: PublicKeyCredentialRP(name: configuration.relyingPartyName, id: configuration.relyingPartyID),
            user: PublicKeyCredentialUser(
                id: Base64URL.encode(userID),
                name: username,
                displayName: body.displayName ?? username
            ),
            pubKeyCredParams: [PublicKeyCredentialParameter(type: "public-key", alg: -7)],
            timeout: 60_000,
            attestation: "none",
            excludeCredentials: existingCredential.map {
                [CredentialDescriptor(type: "public-key", id: Base64URL.encode($0.credentialID))]
            } ?? []
        )
        return try jsonResponse(status: .ok, body: response)
    }

    private func completeRegistration(for request: HTTPRequestAccumulator, logger: Logger) async throws -> HTTPResponsePayload {
        let body = try decode(RegisterCompleteRequest.self, from: request.body)
        logger.info("Registration completion received", metadata: ["username": .string(body.username)])

        let challenge = try await store.takeChallenge(username: body.username, kind: .registration)
        let attestationObject = try Base64URL.decode(body.credential.attestationObject)
        let clientDataJSON = try Base64URL.decode(body.credential.clientDataJSON)
        let attestation = try webAuthnVerifier.parseAttestation(
            attestationObject: attestationObject,
            clientDataJSON: clientDataJSON,
            expectedChallenge: challenge.challenge,
            config: configuration
        )

        if let existingCredential = try await store.credential(for: body.username),
           existingCredential.credentialID != attestation.credentialID {
            throw HTTPError.conflict("Username \(body.username) is already registered with a different passkey")
        }

        try await store.saveCredential(
            StoredCredential(
                credentialID: attestation.credentialID,
                username: body.username,
                userID: challenge.userID,
                publicKeyX963: attestation.publicKeyX963,
                signCount: attestation.signCount
            )
        )
        logger.info(
            "Registration completed",
            metadata: [
                "username": .string(body.username),
                "credential_id": .string(Base64URL.encode(attestation.credentialID)),
            ]
        )
        return try jsonResponse(status: .created, body: ["status": "registered"])
    }

    private func beginAuthentication(for request: HTTPRequestAccumulator, logger: Logger) async throws -> HTTPResponsePayload {
        let body = try decode(AuthenticateBeginRequest.self, from: request.body)
        logger.info("Authentication started", metadata: ["username": .string(body.username)])

        guard let credential = try await store.credential(for: body.username) else {
            throw HTTPError.notFound("No passkey registered for \(body.username)")
        }

        let challenge = randomBytes(count: 32)
        try await store.saveChallenge(
            ChallengeRecord(
                challenge: challenge,
                username: body.username,
                userID: credential.userID,
                kind: .authentication,
                expiresAt: Date().addingTimeInterval(300)
            )
        )

        let response = AuthenticateBeginResponse(
            challenge: Base64URL.encode(challenge),
            timeout: 60_000,
            rpId: configuration.relyingPartyID,
            allowCredentials: [
                CredentialDescriptor(type: "public-key", id: Base64URL.encode(credential.credentialID))
            ],
            userVerification: "preferred"
        )
        return try jsonResponse(status: .ok, body: response)
    }

    private func completeAuthentication(for request: HTTPRequestAccumulator, logger: Logger) async throws -> HTTPResponsePayload {
        let body = try decode(AuthenticateCompleteRequest.self, from: request.body)
        logger.info("Authentication completion received", metadata: ["username": .string(body.username)])

        guard let storedCredential = try await store.credential(for: body.username) else {
            throw HTTPError.notFound("No passkey registered for \(body.username)")
        }

        let challenge = try await store.takeChallenge(username: body.username, kind: .authentication)
        let assertion = try webAuthnVerifier.verifyAssertion(
            credential: body.credential,
            storedCredential: storedCredential,
            expectedChallenge: challenge.challenge,
            config: configuration
        )
        try await store.updateSignCount(username: body.username, signCount: assertion.newSignCount)
        logger.info(
            "Authentication completed",
            metadata: [
                "username": .string(body.username),
                "credential_id": .string(Base64URL.encode(assertion.credentialID)),
            ]
        )
        return try jsonResponse(
            status: .ok,
            body: try jwtService.issueToken(username: body.username, credentialID: assertion.credentialID)
        )
    }

    private func currentUserResponse(for request: HTTPRequestAccumulator, logger: Logger) throws -> HTTPResponsePayload {
        logger.debug("Inspecting current user")
        let me = try jwtService.verifyBearerToken(request.headers["Authorization"].first)
        return try jsonResponse(status: .ok, body: me)
    }

    private func decode<T: Decodable>(_ type: T.Type, from body: Data) throws -> T {
        do {
            return try JSONDecoder.apiDecoder.decode(type, from: body)
        } catch {
            throw HTTPError.badRequest("Invalid request JSON: \(error)")
        }
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
