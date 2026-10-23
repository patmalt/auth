import Foundation

struct RegistrationCredential: Codable {
    let id: String
    let rawID: String
    let type: String
    let attestationObject: String
    let clientDataJSON: String
}

struct AssertionCredential: Codable {
    let id: String
    let rawID: String
    let type: String
    let authenticatorData: String
    let clientDataJSON: String
    let signature: String
    let userHandle: String?
}

struct HealthResponse: Codable { let status: String; let service: String }
struct ErrorEnvelope: Codable { let error: String }
