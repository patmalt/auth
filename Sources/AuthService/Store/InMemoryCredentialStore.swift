import Foundation

actor InMemoryCredentialStore: CredentialStoring {
    private var credentialsByUsername: [String: StoredCredential] = [:]
    private var challengesByUsername: [String: ChallengeRecord] = [:]

    func saveChallenge(_ challenge: ChallengeRecord) async throws {
        challengesByUsername[challenge.username] = challenge
    }

    func takeChallenge(username: String, kind: ChallengeKind) async throws -> ChallengeRecord {
        guard let challenge = challengesByUsername.removeValue(forKey: username) else {
            throw HTTPError.badRequest("No active challenge for \(username)")
        }
        guard challenge.kind == kind else {
            throw HTTPError.badRequest("Challenge kind mismatch")
        }
        guard challenge.expiresAt > Date() else {
            throw HTTPError.badRequest("Challenge expired")
        }
        return challenge
    }

    func credential(for username: String) async throws -> StoredCredential? {
        credentialsByUsername[username]
    }

    func saveCredential(_ credential: StoredCredential) async throws {
        credentialsByUsername[credential.username] = credential
    }

    func updateSignCount(username: String, signCount: UInt32) async throws {
        guard var credential = credentialsByUsername[username] else {
            return
        }
        credential.signCount = signCount
        credentialsByUsername[username] = credential
    }
}
