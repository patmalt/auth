import Foundation

struct StoredCredential: Codable {
    let credentialID: Data
    let username: String
    let userID: Data
    let publicKeyX963: Data
    var signCount: UInt32
}
