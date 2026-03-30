import Foundation

struct StoredCredential: Codable {
    let credentialID: Data
    let username: String
    let userID: Data
    let publicKeyX963: Data
    var signCount: UInt32
}

struct ChallengeRecord {
    let challenge: Data
    let username: String
    let userID: Data
    let kind: ChallengeKind
    let expiresAt: Date
}

enum ChallengeKind: String {
    case registration
    case authentication
}
