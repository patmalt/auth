#if os(iOS) || os(macOS)
import CryptoKit
import Foundation
import Security

struct OIDCDiscovery: Decodable, Sendable {
    let issuer: String
    let authorization_endpoint: URL
    let token_endpoint: URL
    let userinfo_endpoint: URL
    let jwks_uri: URL
    let revocation_endpoint: URL
    let code_challenge_methods_supported: [String]
}
struct OIDCTokens: Decodable, Sendable {
    let access_token: String
    let token_type: String
    let id_token: String
    let refresh_token: String?
}
struct OIDCClaims: Decodable, Sendable {
    let iss: String
    let sub: String
    let aud: String
    let azp: String?
    let exp: Double
    let iat: Double
    let nbf: Double?
    let nonce: String?
}
private struct JWTHeader: Decodable { let alg: String; let kid: String; let crit: [String]? }
private struct JWKS: Decodable {
    struct Key: Decodable { let kty: String; let crv: String?; let kid: String?; let alg: String?; let use: String?; let x: String?; let y: String? }
    let keys: [Key]
}
struct OIDCProfile: Decodable, Sendable { let sub: String; let preferred_username: String? }
private struct SavedOIDCSession: Codable { let refreshToken: String; let subject: String }
private struct OIDCClientError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

// Owns authentication state and networking independently of the UI executor.
actor OIDCClient {
    private let issuer: URL
    private let clientID: String
    private let redirectURI: URL
    private var accessToken: String?
    private var subject: String?
    private var expires = Date.distantPast
    // Actor methods can reenter at suspension points. Keep each token operation exclusive across awaits.
    private var busy = false
    private var keychainService: String { "com.patmalt.oidc." + Self.encode(Data((issuer.absoluteString + "|" + clientID + "|" + redirectURI.absoluteString).utf8).sha256Data) }

    init(issuer: URL, clientID: String, redirectURI: URL) {
        self.issuer = issuer; self.clientID = clientID; self.redirectURI = redirectURI
    }

    func signIn() async throws -> String {
        guard !busy else { throw OIDCClientError(message: "An authentication operation is already in progress") }
        busy = true; defer { busy = false }
        let metadata = try await discover()
        let state = Self.random(), nonce = Self.random(), verifier = Self.random()
        var components = URLComponents(url: metadata.authorization_endpoint, resolvingAgainstBaseURL: false)!
        components.queryItems = ["client_id": clientID, "redirect_uri": redirectURI.absoluteString, "response_type": "code",
            "scope": "openid profile offline_access", "state": state, "nonce": nonce,
            "code_challenge": Self.encode(Data(verifier.utf8).sha256Data), "code_challenge_method": "S256"].map { URLQueryItem(name: $0.key, value: $0.value) }
        let started = Date()
        let callback = try await authenticate(url: components.url!)
        guard Date().timeIntervalSince(started) <= 300, callback.scheme == redirectURI.scheme,
              callback.host == redirectURI.host, callback.path == redirectURI.path, callback.fragment == nil,
              let params = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems else {
            throw OIDCClientError(message: "Invalid authorization callback")
        }
        func value(_ key: String) throws -> String? {
            let found = params.filter { $0.name == key }
            guard found.count <= 1 else { throw OIDCClientError(message: "Duplicate callback parameter") }
            return found.first?.value
        }
        guard try value("state") == state, try value("iss") == issuer.absoluteString else { throw OIDCClientError(message: "Authorization state or issuer mismatch") }
        if let error = try value("error") { throw OIDCClientError(message: error) }
        guard let code = try value("code") else { throw OIDCClientError(message: "Missing authorization code") }
        let tokens: OIDCTokens = try await form(metadata.token_endpoint, ["grant_type": "authorization_code", "client_id": clientID,
            "redirect_uri": redirectURI.absoluteString, "code": code, "code_verifier": verifier])
        let claims = try await validate(tokens, metadata: metadata, nonce: nonce)
        try install(tokens, claims: claims)
        return claims.sub
    }

    func refresh() async throws -> String {
        guard !busy else { throw OIDCClientError(message: "An authentication operation is already in progress") }
        busy = true; defer { busy = false }
        return try await refreshSession()
    }

    private func refreshSession() async throws -> String {
        guard let saved = try readSaved() else { throw OIDCClientError(message: "Sign in first") }
        let metadata = try await discover()
        // Refreshes are serialized. A lost refresh response requires sign-in again; never replay the old token.
        try deleteSaved()
        accessToken = nil; subject = nil; expires = .distantPast
        let tokens: OIDCTokens = try await form(metadata.token_endpoint, ["grant_type": "refresh_token", "client_id": clientID, "refresh_token": saved.refreshToken])
        let claims = try await validate(tokens, metadata: metadata, subject: saved.subject)
        try install(tokens, claims: claims)
        return claims.sub
    }

    func profile() async throws -> OIDCProfile {
        guard !busy else { throw OIDCClientError(message: "An authentication operation is already in progress") }
        busy = true; defer { busy = false }
        if accessToken == nil || expires <= Date() { _ = try await refreshSession() }
        let metadata = try await discover()
        guard let accessToken else { throw OIDCClientError(message: "Sign in first") }
        var request = URLRequest(url: metadata.userinfo_endpoint)
        request.setValue("Bearer " + accessToken, forHTTPHeaderField: "Authorization")
        let info: OIDCProfile = try await send(request)
        guard info.sub == subject else { throw OIDCClientError(message: "UserInfo subject mismatch") }
        return info
    }

    func signOut() async throws {
        guard !busy else { throw OIDCClientError(message: "An authentication operation is already in progress") }
        busy = true; defer { busy = false }
        let token = try readSaved()?.refreshToken ?? accessToken
        try deleteSaved(); accessToken = nil; subject = nil; expires = .distantPast
        if let token {
            let metadata = try await discover()
            _ = try await raw(formRequest(metadata.revocation_endpoint, ["client_id": clientID, "token": token]))
        }
    }

    private func install(_ tokens: OIDCTokens, claims: OIDCClaims) throws {
        guard let refresh = tokens.refresh_token, !refresh.isEmpty else { throw OIDCClientError(message: "Missing replacement refresh token") }
        try save(SavedOIDCSession(refreshToken: refresh, subject: claims.sub))
        accessToken = tokens.access_token; subject = claims.sub; expires = Date(timeIntervalSince1970: claims.exp)
    }

    private func discover() async throws -> OIDCDiscovery {
        guard issuer.scheme == "https", issuer.user == nil, issuer.password == nil, issuer.query == nil, issuer.fragment == nil,
              issuer.path.isEmpty || issuer.path == "/", !issuer.absoluteString.hasSuffix("/") else {
            throw OIDCClientError(message: "Configure an HTTPS issuer origin without a trailing slash")
        }
        let metadata: OIDCDiscovery = try await send(URLRequest(url: issuer.appending(path: ".well-known/openid-configuration")))
        guard metadata.issuer == issuer.absoluteString, metadata.code_challenge_methods_supported.contains("S256") else {
            throw OIDCClientError(message: "Invalid discovery document")
        }
        for url in [metadata.authorization_endpoint, metadata.token_endpoint, metadata.userinfo_endpoint, metadata.jwks_uri, metadata.revocation_endpoint] {
            guard url.scheme == "https", url.host == issuer.host, url.port == issuer.port, url.user == nil, url.password == nil, url.fragment == nil else {
                throw OIDCClientError(message: "Unexpected discovery endpoint")
            }
        }
        return metadata
    }

    private func validate(_ tokens: OIDCTokens, metadata: OIDCDiscovery, nonce: String? = nil, subject: String? = nil) async throws -> OIDCClaims {
        guard tokens.token_type.lowercased() == "bearer", !tokens.access_token.isEmpty else { throw OIDCClientError(message: "Invalid token response") }
        let parts = tokens.id_token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw OIDCClientError(message: "Malformed ID token") }
        let header = try JSONDecoder().decode(JWTHeader.self, from: Self.decode(String(parts[0])))
        guard header.alg == "ES256", header.crit == nil else { throw OIDCClientError(message: "Unsupported ID token header") }
        let jwks: JWKS = try await send(URLRequest(url: metadata.jwks_uri))
        let matches = jwks.keys.filter { $0.kid == header.kid && $0.kty == "EC" && $0.crv == "P-256" && $0.use == "sig" && $0.alg == "ES256" }
        guard matches.count == 1, let x = matches[0].x, let y = matches[0].y else { throw OIDCClientError(message: "Unknown signing key") }
        let rawKey = try Self.decode(x) + Self.decode(y)
        let key = try P256.Signing.PublicKey(rawRepresentation: rawKey)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Self.decode(String(parts[2])))
        guard key.isValidSignature(signature, for: Data((String(parts[0]) + "." + String(parts[1])).utf8)) else { throw OIDCClientError(message: "Invalid ID token signature") }
        let claims = try JSONDecoder().decode(OIDCClaims.self, from: Self.decode(String(parts[1])))
        let now = Date().timeIntervalSince1970
        guard claims.iss == issuer.absoluteString, claims.aud == clientID, claims.azp == nil || claims.azp == clientID,
              !claims.sub.isEmpty, claims.exp > now, claims.iat <= now + 60, claims.exp > claims.iat,
              claims.nbf == nil || claims.nbf! <= now + 60,
              nonce == nil || claims.nonce == nonce, subject == nil || claims.sub == subject else {
            throw OIDCClientError(message: "Invalid ID token claims")
        }
        return claims
    }

    private func authenticate(url: URL) async throws -> URL {
        let presenter = await OIDCBrowserSession()
        return try await presenter.authenticate(url: url, callbackURLScheme: redirectURI.scheme)
    }

    private func formRequest(_ url: URL, _ fields: [String: String]) -> URLRequest {
        var components = URLComponents()
        components.queryItems = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
        var request = URLRequest(url: url); request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data((components.percentEncodedQuery ?? "").replacingOccurrences(of: "+", with: "%2B").utf8)
        return request
    }
    private func form<T: Decodable>(_ url: URL, _ fields: [String: String]) async throws -> T { try await send(formRequest(url, fields)) }
    private func send<T: Decodable>(_ request: URLRequest) async throws -> T { try JSONDecoder().decode(T.self, from: await raw(request)) }
    private func raw(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw OIDCClientError(message: "OIDC request failed; sign in again if the session expired")
        }
        return data
    }

    private var keychainQuery: [String: Any] { [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService, kSecAttrAccount as String: "session"] }
    private func readSaved() throws -> SavedOIDCSession? {
        var query = keychainQuery; query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw OIDCClientError(message: "Keychain read failed") }
        return try JSONDecoder().decode(SavedOIDCSession.self, from: data)
    }
    private func save(_ value: SavedOIDCSession) throws {
        let data = try JSONEncoder().encode(value)
        let update = SecItemUpdate(keychainQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw OIDCClientError(message: "Keychain update failed") }
        var query = keychainQuery; query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw OIDCClientError(message: "Keychain save failed") }
    }
    private func deleteSaved() throws {
        let status = SecItemDelete(keychainQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw OIDCClientError(message: "Keychain delete failed") }
    }
    private static func random() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        precondition(SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess)
        return encode(Data(bytes))
    }
    private static func encode(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private static func decode(_ value: String) throws -> Data {
        let padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/").padding(toLength: ((value.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: padded) else { throw OIDCClientError(message: "Invalid base64url") }
        return data
    }
}
private extension Data { var sha256Data: Data { Data(SHA256.hash(data: self)) } }
#endif
