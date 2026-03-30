import Foundation

struct RegisterBeginRequest: Codable {
    let username: String
    let displayName: String?
}

struct RegisterBeginResponse: Codable {
    let challenge: String
    let rp: PublicKeyCredentialRP
    let user: PublicKeyCredentialUser
    let pubKeyCredParams: [PublicKeyCredentialParameter]
    let timeout: Int
    let attestation: String
    let excludeCredentials: [CredentialDescriptor]
}

struct AuthenticateBeginRequest: Codable {
    let username: String
}

struct AuthenticateBeginResponse: Codable {
    let challenge: String
    let timeout: Int
    let rpId: String
    let allowCredentials: [CredentialDescriptor]
    let userVerification: String
}

struct RegisterCompleteRequest: Codable {
    let username: String
    let credential: RegistrationCredential
}

struct AuthenticateCompleteRequest: Codable {
    let username: String
    let credential: AssertionCredential
}

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

struct AuthTokenResponse: Codable {
    let accessToken: String
    let tokenType: String
    let expiresAt: String
    let credentialID: String
}

struct HealthResponse: Codable {
    let status: String
    let service: String
}

struct MeResponse: Codable {
    let subject: String
    let username: String
    let credentialID: String
}

struct PublicKeyCredentialRP: Codable {
    let name: String
    let id: String
}

struct PublicKeyCredentialUser: Codable {
    let id: String
    let name: String
    let displayName: String
}

struct PublicKeyCredentialParameter: Codable {
    let type: String
    let alg: Int
}

struct CredentialDescriptor: Codable {
    let type: String
    let id: String
}

struct ErrorEnvelope: Codable {
    let error: String
}
