import Foundation
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1

final class HTTPRequestHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let server: AuthServer
    private let logger: Logger
    private let currentRequestBox: NIOLoopBoundBox<HTTPRequestAccumulator?>

    init(server: AuthServer, logger: Logger, eventLoop: EventLoop) {
        self.server = server
        self.logger = logger
        self.currentRequestBox = .makeEmptyBox(valueType: HTTPRequestAccumulator.self, eventLoop: eventLoop)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        switch part {
        case .head(let head):
            currentRequestBox.value = HTTPRequestAccumulator(method: head.method, uri: head.uri, headers: head.headers, body: Data())
        case .body(var buffer):
            if let bytes = buffer.readBytes(length: buffer.readableBytes) {
                if currentRequestBox.value == nil {
                    currentRequestBox.value = HTTPRequestAccumulator()
                }
                currentRequestBox.value?.body.append(contentsOf: bytes)
            }
        case .end:
            handleCompletedRequest(context: context)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Channel error", metadata: ["error": .string(String(describing: error))])
        writeError(.internalServerError("Channel error: \(error)"), requestID: UUID().uuidString.lowercased(), context: context)
    }

    private func handleCompletedRequest(context: ChannelHandlerContext) {
        let request = currentRequestBox.value ?? HTTPRequestAccumulator()
        currentRequestBox.value = nil

        let requestContext = RequestContext(
            requestID: request.headers.requestID(),
            method: request.method.rawValue,
            path: request.uri,
            clientIP: request.headers.clientIP(),
            userAgent: request.headers.first(name: "user-agent")
        )
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let logger = logger.with(request: requestContext)

        context.eventLoop.makeFutureWithTask { [server] in
            await server.respond(to: request, context: requestContext)
        }.whenSuccess { response in
            let metadata: Logger.Metadata = [
                "status_code": .stringConvertible(response.status.code),
                "response_bytes": .stringConvertible(response.body.count),
            ]
            if response.status.code >= 500 {
                logger.error("Request failed", metadata: metadata)
            } else if response.status.code >= 400 {
                logger.warning("Request failed", metadata: metadata)
            } else {
                logger.info("Request completed", metadata: metadata)
            }
            self.writeResponse(response, requestID: requestContext.requestID, context: boundContext.value)
        }
    }

    private func writeResponse(_ response: HTTPResponsePayload, requestID: String, context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        response.headers.forEach { headers.add(name: $0.key, value: $0.value) }
        headers.add(name: "Content-Length", value: "\(response.body.count)")
        headers.add(name: "X-Request-ID", value: requestID)

        context.write(wrapOutboundOut(.head(.init(version: .http1_1, status: response.status, headers: headers))), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: response.body.count)
        buffer.writeBytes(response.body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    private func writeError(_ error: HTTPError, requestID: String, context: ChannelHandlerContext) {
        let payload = (try? JSONEncoder.apiEncoder.encode(ErrorEnvelope(error: error.message)))
            ?? Data("{\"error\":\"\(error.message)\"}".utf8)
        writeResponse(
            HTTPResponsePayload(
                status: HTTPResponseStatus(statusCode: error.statusCode),
                headers: ["Content-Type": "application/json"],
                body: payload
            ),
            requestID: requestID,
            context: context
        )
    }
}
