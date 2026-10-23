import Foundation

actor InMemoryCredentialStore: CredentialStoring {
    private var credentialsByUsername: [String: StoredCredential] = [:]
    func credential(for username: String) async throws -> StoredCredential? {
        credentialsByUsername[username]
    }

    func saveCredential(_ credential: StoredCredential) async throws {
        guard credentialsByUsername[credential.username] == nil else { throw HTTPError.conflict("Username already registered") }
        credentialsByUsername[credential.username] = credential
    }

    func updateSignCount(username: String, signCount: UInt32) async throws {
        guard var credential = credentialsByUsername[username] else {
            return
        }
        guard signCount >= credential.signCount else { throw HTTPError.unauthorized("Authenticator sign count regressed") }
        credential.signCount = signCount
        credentialsByUsername[username] = credential
    }
}

