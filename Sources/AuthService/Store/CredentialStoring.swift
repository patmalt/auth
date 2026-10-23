protocol CredentialStoring: Actor {
    func credential(for username: String) async throws -> StoredCredential?
    func saveCredential(_ credential: StoredCredential) async throws
    func updateSignCount(username: String, signCount: UInt32) async throws
}

enum CredentialStoreFactory {
    static func makeStore(configuration: ServiceConfiguration) async throws -> any CredentialStoring {
        switch configuration.storeDriver.lowercased() {
        case "memory":
            InMemoryCredentialStore()
        case "dynamodb":
            try await DynamoDBCredentialStore(configuration: configuration)
        default:
            throw HTTPError.internalServerError("Unsupported store driver \(configuration.storeDriver)")
        }
    }
}

