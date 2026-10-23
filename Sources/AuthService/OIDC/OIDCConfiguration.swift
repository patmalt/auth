import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

struct OIDCClient: Codable, Sendable {
    let clientID: String
    let redirectURIs: [String]
}

struct OIDCConfiguration: Sendable {
    let issuer: String
    let clients: [OIDCClient]
    let signingKey: P256.Signing.PrivateKey
    var keyID: String { Base64URL.encode(Data(signingKey.publicKey.rawRepresentation).sha256()) }

    static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws -> Self? {
        guard let issuer = env["OIDC_ISSUER"] else { return nil }
        guard let json = env["OIDC_CLIENTS_JSON"], let pem = env["OIDC_SIGNING_KEY_PEM"] else {
            throw HTTPError.internalServerError("OIDC requires OIDC_CLIENTS_JSON and OIDC_SIGNING_KEY_PEM")
        }
        let clients = try JSONDecoder().decode([OIDCClient].self, from: Data(json.utf8))
        let key = try P256.Signing.PrivateKey(pemRepresentation: pem)
        let config = Self(issuer: issuer, clients: clients, signingKey: key)
        try config.validate()
        return config
    }

    func validate() throws {
        guard let url = URLComponents(string: issuer), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty, !issuer.hasSuffix("/"), !clients.isEmpty,
              Set(clients.map(\.clientID)).count == clients.count else {
            throw HTTPError.internalServerError("OIDC issuer must be an HTTPS origin; client IDs must be unique")
        }
        for client in clients {
            guard !client.clientID.isEmpty, !client.redirectURIs.isEmpty else {
                throw HTTPError.internalServerError("OIDC clients require an ID and redirect URIs")
            }
            for redirect in client.redirectURIs {
                guard let url = URLComponents(string: redirect), let scheme = url.scheme,
                      url.fragment == nil, url.user == nil, url.password == nil,
                      !redirect.contains("*"), !redirect.contains(where: { $0.isWhitespace }),
                      (scheme == "https" && url.host != nil) ||
                      (scheme == "http" && ["127.0.0.1", "[::1]"].contains(url.host ?? "")) ||
                      (scheme.contains(".") && url.host == nil) else {
                    throw HTTPError.internalServerError("Invalid OIDC redirect URI: \(redirect)")
                }
            }
        }
    }
}

struct OIDCSigner: Sendable {
    let configuration: OIDCConfiguration

    func sign(_ claims: [String: Any]) throws -> String {
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "JWT", "kid": configuration.keyID])
        let payload = try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])
        let input = Base64URL.encode(header) + "." + Base64URL.encode(payload)
        let signature = try configuration.signingKey.signature(for: Data(input.utf8))
        return input + "." + Base64URL.encode(signature.rawRepresentation)
    }

    var jwk: [String: String] {
        let raw = configuration.signingKey.publicKey.rawRepresentation
        return ["kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": configuration.keyID,
                "x": Base64URL.encode(Data(raw.prefix(32))), "y": Base64URL.encode(Data(raw.suffix(32)))]
    }
}
