#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct JWTService {
    private let configuration: ServiceConfiguration

    init(configuration: ServiceConfiguration) {
        self.configuration = configuration
    }

    func issueToken(username: String, credentialID: Data) throws -> AuthTokenResponse {
        let now = Date()
        let expiration = now.addingTimeInterval(configuration.tokenLifetime)
        let header = ["alg": "HS256", "typ": "JWT"]
        let payload: [String: Any] = [
            "sub": "\(username):\(Base64URL.encode(credentialID))",
            "username": username,
            "credential_id": Base64URL.encode(credentialID),
            "iss": configuration.jwtIssuer,
            "aud": configuration.jwtAudience,
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(expiration.timeIntervalSince1970),
        ]

        let headerData = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let signingInput = "\(Base64URL.encode(headerData)).\(Base64URL.encode(payloadData))"
        let secret = SymmetricKey(data: Data(configuration.jwtSecret.utf8))
        let signature = HMAC<SHA256>.authenticationCode(for: Data(signingInput.utf8), using: secret)
        let token = "\(signingInput).\(Base64URL.encode(Data(signature)))"

        return AuthTokenResponse(
            accessToken: token,
            tokenType: "Bearer",
            expiresAt: utcTimestampString(for: expiration),
            credentialID: Base64URL.encode(credentialID)
        )
    }

    func verifyBearerToken(_ headerValue: String?) throws -> MeResponse {
        guard let headerValue, headerValue.hasPrefix("Bearer ") else {
            throw HTTPError.unauthorized("Missing bearer token")
        }
        let token = String(headerValue.dropFirst("Bearer ".count))
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else {
            throw HTTPError.unauthorized("Malformed JWT")
        }

        let signingInput = "\(segments[0]).\(segments[1])"
        let secret = SymmetricKey(data: Data(configuration.jwtSecret.utf8))
        let expected = HMAC<SHA256>.authenticationCode(for: Data(signingInput.utf8), using: secret)
        let actual = try Base64URL.decode(String(segments[2]))
        guard Data(expected) == actual else {
            throw HTTPError.unauthorized("JWT signature mismatch")
        }

        let payloadData = try Base64URL.decode(String(segments[1]))
        guard let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw HTTPError.unauthorized("JWT payload could not be decoded")
        }
        guard let expiration = payload["exp"] as? Double ?? (payload["exp"] as? Int).map(Double.init),
              Date().timeIntervalSince1970 < expiration else {
            throw HTTPError.unauthorized("JWT has expired")
        }
        guard let subject = payload["sub"] as? String,
              let username = payload["username"] as? String,
              let credentialID = payload["credential_id"] as? String else {
            throw HTTPError.unauthorized("JWT is missing required claims")
        }

        return MeResponse(subject: subject, username: username, credentialID: credentialID)
    }
}
