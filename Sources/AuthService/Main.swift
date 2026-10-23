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
            guard configuration.origin == oidcConfiguration.issuer else {
                throw HTTPError.internalServerError("RP_ORIGIN must equal OIDC_ISSUER")
            }
            let grants: any GrantStoring
            if configuration.storeDriver.lowercased() == "memory" {
                logger.warning("Explicit memory mode is for local development only; sessions are lost on restart")
                grants = InMemoryGrantStore()
            } else {
                grants = try await DynamoDBGrantStore(region: configuration.awsRegion,
                    table: ProcessInfo.processInfo.environment["DYNAMODB_OIDC_TABLE"] ?? "OIDCGrants")
            }
            let oidc = OIDCProvider(configuration: oidcConfiguration, service: configuration, store: store, grants: grants)
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

