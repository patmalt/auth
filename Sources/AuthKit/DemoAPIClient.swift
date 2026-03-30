#if os(iOS) || os(macOS)
import Foundation

actor DemoAPIClient {
    private let baseURL: URL
    private let session: URLSession
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    func beginRegistration(username: String) async throws -> RegisterBeginResponseDTO {
        try await send(
            path: "/register/begin",
            body: RegisterBeginDTO(username: username, displayName: username)
        )
    }

    func completeRegistration(username: String, credential: RegistrationCredentialDTO) async throws {
        let _: StatusEnvelope = try await send(
            path: "/register/complete",
            body: RegisterCompleteDTO(username: username, credential: credential)
        )
    }

    func beginAuthentication(username: String) async throws -> AuthenticateBeginResponseDTO {
        try await send(
            path: "/authenticate/begin",
            body: UsernameDTO(username: username)
        )
    }

    func completeAuthentication(username: String, credential: AssertionCredentialDTO) async throws -> TokenResponseDTO {
        try await send(
            path: "/authenticate/complete",
            body: AuthenticateCompleteDTO(username: username, credential: credential)
        )
    }

    func me(token: String) async throws -> MeResponseDTO {
        var request = URLRequest(url: baseURL.appending(path: "/me"))
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        try validate(response: response, data: data)
        return try decoder.decode(MeResponseDTO.self, from: data)
    }

    private func send<Request: Encodable & Sendable, Response: Decodable & Sendable>(path: String, body: Request) async throws -> Response {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(body)
        let (data, response) = try await session.data(for: request)
        try validate(response: response, data: data)
        return try decoder.decode(Response.self, from: data)
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let response = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard (200..<300).contains(response.statusCode) else {
            let message = (try? decoder.decode(ErrorEnvelopeDTO.self, from: data).error) ?? "Request failed"
            throw NSError(domain: "DemoAPIClient", code: response.statusCode, userInfo: [NSLocalizedDescriptionKey: message])
        }
    }
}

struct RegisterBeginDTO: Codable, Sendable {
    let username: String
    let displayName: String
}

struct RegisterCompleteDTO: Codable, Sendable {
    let username: String
    let credential: RegistrationCredentialDTO
}

struct AuthenticateCompleteDTO: Codable, Sendable {
    let username: String
    let credential: AssertionCredentialDTO
}

struct UsernameDTO: Codable, Sendable {
    let username: String
}

struct StatusEnvelope: Codable, Sendable {
    let status: String
}

struct ErrorEnvelopeDTO: Codable, Sendable {
    let error: String
}

struct RegisterBeginResponseDTO: Codable, Sendable {
    let challenge: String
    let rp: RPDTO
    let user: UserDTO
    let pubKeyCredParams: [CredentialParameterDTO]
    let timeout: Int
    let attestation: String
    let excludeCredentials: [CredentialDescriptorDTO]
}

struct AuthenticateBeginResponseDTO: Codable, Sendable {
    let challenge: String
    let timeout: Int
    let rpId: String
    let allowCredentials: [CredentialDescriptorDTO]
    let userVerification: String
}

struct RPDTO: Codable, Sendable {
    let name: String
    let id: String
}

struct UserDTO: Codable, Sendable {
    let id: String
    let name: String
    let displayName: String
}

struct CredentialParameterDTO: Codable, Sendable {
    let type: String
    let alg: Int
}

struct CredentialDescriptorDTO: Codable, Sendable {
    let type: String
    let id: String
}

struct RegistrationCredentialDTO: Codable, Sendable {
    let id: String
    let rawID: String
    let type: String
    let attestationObject: String
    let clientDataJSON: String
}

struct AssertionCredentialDTO: Codable, Sendable {
    let id: String
    let rawID: String
    let type: String
    let authenticatorData: String
    let clientDataJSON: String
    let signature: String
    let userHandle: String?
}

struct TokenResponseDTO: Codable, Sendable {
    let accessToken: String
    let tokenType: String
    let expiresAt: String
    let credentialID: String
}

struct MeResponseDTO: Codable, Sendable {
    let subject: String
    let username: String
    let credentialID: String
}
#endif
