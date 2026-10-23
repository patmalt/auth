import Foundation
import Logging

@main
enum ServiceMain {
    static func main() async {
        let configuration = ServiceConfiguration.fromEnvironment()
        let logger = Logger.makeAuthLogger(configuration: configuration)

        do {
            logger.info("Starting auth service")
            let store = try await CredentialStoreFactory.makeStore(configuration: configuration)
            let oidcConfiguration = try OIDCConfiguration.fromEnvironment()
            if let oidcConfiguration {
                guard configuration.origin == oidcConfiguration.issuer else {
                    throw HTTPError.internalServerError("RP_ORIGIN must equal OIDC_ISSUER")
                }
                logger.warning("OIDC uses process-local grants: run exactly one instance; restart invalidates sessions")
            }
            let oidc = oidcConfiguration.map { OIDCProvider(configuration: $0, service: configuration, store: store) }
            let server = AuthServer(configuration: configuration, store: store, logger: logger, oidc: oidc)
            try await server.run()
        } catch {
            logger.critical("Server failed to start", metadata: ["error": .string(String(describing: error))])
            let message = "Server failed to start: \(error)\n"
            if let data = message.data(using: .utf8) {
                try? FileHandle.standardError.write(contentsOf: data)
            }
            exit(1)
        }
    }
}

