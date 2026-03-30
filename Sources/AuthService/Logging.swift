import Foundation
import Logging
import NIOHTTP1

struct RequestContext: Sendable {
    let requestID: String
    let method: String
    let path: String
    let clientIP: String?
    let userAgent: String?
}

extension Logger.Level {
    init(environmentVariable value: String?) {
        switch value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "trace":
            self = .trace
        case "debug":
            self = .debug
        case "notice":
            self = .notice
        case "warning":
            self = .warning
        case "error":
            self = .error
        case "critical":
            self = .critical
        default:
            self = .info
        }
    }
}

extension Logger {
    static func makeAuthLogger(configuration: ServiceConfiguration) -> Logger {
        LoggingSystem.bootstrap(StreamLogHandler.standardOutput)
        var logger = Logger(label: "auth.service")
        logger.logLevel = configuration.logLevel
        logger[metadataKey: "service"] = "AuthService"
        logger[metadataKey: "store_driver"] = .string(configuration.storeDriver)
        logger[metadataKey: "aws_region"] = .string(configuration.awsRegion)
        logger[metadataKey: "rp_id"] = .string(configuration.relyingPartyID)
        return logger
    }

    func with(request context: RequestContext) -> Logger {
        var logger = self
        logger[metadataKey: "request_id"] = .string(context.requestID)
        logger[metadataKey: "http_method"] = .string(context.method)
        logger[metadataKey: "path"] = .string(context.path)
        if let clientIP = context.clientIP {
            logger[metadataKey: "client_ip"] = .string(clientIP)
        }
        if let userAgent = context.userAgent {
            logger[metadataKey: "user_agent"] = .string(userAgent)
        }
        return logger
    }
}

extension HTTPHeaders {
    func requestID() -> String {
        first(name: "x-request-id")
            ?? first(name: "x-amzn-trace-id")
            ?? UUID().uuidString.lowercased()
    }

    func clientIP() -> String? {
        first(name: "x-forwarded-for")?
            .split(separator: ",")
            .first
            .map { $0.trimmingCharacters(in: .whitespaces) }
    }
}
