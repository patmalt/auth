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
            let server = AuthServer(configuration: configuration, store: store, logger: logger)
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
