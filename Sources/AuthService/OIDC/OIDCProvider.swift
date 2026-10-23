import Foundation
import NIOHTTP1

private struct OAuthFailure: Error {
    let code: String
}

private struct Authorization {
    let clientID: String
    let redirectURI: String
    let scope: Set<String>
    let state: String?
    let nonce: String?
    let challenge: String
    let expires: Date
    var username: String?
    var passkeyChallenge: Data?
}

private struct Grant {
    let authorization: Authorization
    let subject: String
    let username: String
    let authTime: Int
    let family: String
    let expires: Date
}

private struct RefreshRecord {
    let grant: Grant
    var used: Bool = false
}

/// All grants are process-local. Actor isolation makes code redemption and refresh rotation atomic.
actor OIDCProvider {
    private let configuration: OIDCConfiguration
    private let service: ServiceConfiguration
    private let store: any CredentialStoring
    private let verifier: any WebAuthnVerifying
    private var pending: [String: Authorization] = [:]
    private var codes: [String: Grant] = [:]
    private var access: [String: Grant] = [:]
    private var refresh: [String: RefreshRecord] = [:]
    private var revoked: Set<String> = []
    private let now: @Sendable () -> Date

    init(configuration: OIDCConfiguration, service: ServiceConfiguration, store: any CredentialStoring,
         verifier: any WebAuthnVerifying = WebAuthnVerifier(), now: @escaping @Sendable () -> Date = { Date() }) {
        self.configuration = configuration
        self.service = service
        self.store = store
        self.verifier = verifier
        self.now = now
    }

    func respond(to request: HTTPRequestAccumulator) async -> HTTPResponsePayload? {
        let path = String(request.uri.split(separator: "?", maxSplits: 1).first ?? "/")
        let routes = ["/.well-known/openid-configuration", "/oauth/jwks", "/oauth/authorize", "/oauth/login/begin",
                      "/oauth/login/complete", "/oauth/token", "/oauth/userinfo", "/oauth/revoke"]
        guard routes.contains(path) else { return nil }
        cleanup()
        do {
            switch (request.method, path) {
            case (.GET, "/.well-known/openid-configuration"):
                return try json(discovery())
            case (.GET, "/oauth/jwks"):
                return try json(["keys": [OIDCSigner(configuration: configuration).jwk]])
            case (.GET, "/oauth/authorize"):
                return try authorize(request)
            case (.POST, "/oauth/login/begin"):
                return try await beginLogin(request)
            case (.POST, "/oauth/login/complete"):
                return try await completeLogin(request)
            case (.POST, "/oauth/token"):
                return try token(request)
            case (.GET, "/oauth/userinfo"), (.POST, "/oauth/userinfo"):
                return try userInfo(request)
            case (.POST, "/oauth/revoke"):
                return try revoke(request)
            default: throw OAuthFailure(code: "invalid_request")
            }
        } catch let failure as OAuthFailure {
            var response = (try? json(["error": failure.code], status: path == "/oauth/userinfo" ? .unauthorized : .badRequest))
                ?? HTTPResponsePayload(status: .badRequest, headers: [:], body: Data())
            if path == "/oauth/userinfo" {
                var headers = response.headers
                headers["WWW-Authenticate"] = "Bearer error=\"invalid_token\""
                response = HTTPResponsePayload(status: response.status, headers: headers, body: response.body)
            }
            return response
        } catch {
            return try? json(["error": "server_error"], status: .internalServerError)
        }
    }

    private func discovery() -> [String: Any] {
        let issuer = configuration.issuer
        return ["issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize",
                "token_endpoint": issuer + "/oauth/token", "userinfo_endpoint": issuer + "/oauth/userinfo",
                "jwks_uri": issuer + "/oauth/jwks", "revocation_endpoint": issuer + "/oauth/revoke",
                "response_types_supported": ["code"], "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["ES256"],
                "token_endpoint_auth_methods_supported": ["none"], "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "profile", "offline_access"],
                "claims_supported": ["iss", "sub", "aud", "iat", "exp", "nonce", "auth_time", "preferred_username"],
                "claims_parameter_supported": false, "request_parameter_supported": false,
                "request_uri_parameter_supported": false]
    }

    private func authorize(_ request: HTTPRequestAccumulator) throws -> HTTPResponsePayload {
        let parts = request.uri.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let p = try Self.parameters(parts.count == 2 ? String(parts[1]) : "")
        // Never redirect before both client and exact redirect URI have been validated.
        guard let client = configuration.clients.first(where: { $0.clientID == p["client_id"] }),
              let redirect = p["redirect_uri"], client.redirectURIs.contains(redirect) else {
            throw OAuthFailure(code: "invalid_request")
        }
        func fail(_ code: String) throws -> HTTPResponsePayload {
            try redirectResponse(redirect, values: ["error": code, "state": p["state"]])
        }
        guard p["response_type"] == "code" else { return try fail("unsupported_response_type") }
        let scopes = Set((p["scope"] ?? "").split(separator: " ").map(String.init))
        guard scopes.contains("openid"), scopes.isSubset(of: ["openid", "profile", "offline_access"]) else {
            return try fail("invalid_scope")
        }
        guard let challenge = p["code_challenge"], Self.validChallenge(challenge), p["code_challenge_method"] == "S256" else {
            return try fail("invalid_request")
        }
        guard p["response_mode"] == nil || p["response_mode"] == "query",
              p["request"] == nil, p["request_uri"] == nil, p["claims"] == nil,
              p["id_token_hint"] == nil, p["acr_values"] == nil,
              p["nonce"] == nil || !(p["nonce"] ?? "").isEmpty else { return try fail("invalid_request") }
        if let age = p["max_age"], Int(age).map({ $0 >= 0 }) != true { return try fail("invalid_request") }
        if p["prompt"] == "none" { return try fail("login_required") }
        if let prompt = p["prompt"], !["login", "consent", "select_account"].contains(prompt) {
            return try fail("invalid_request")
        }
        guard pending.count < 1000 else { throw OAuthFailure(code: "temporarily_unavailable") }
        let transaction = randomToken()
        pending[hash(transaction)] = Authorization(clientID: client.clientID, redirectURI: redirect, scope: scopes,
            state: p["state"], nonce: p["nonce"], challenge: challenge, expires: now().addingTimeInterval(300))
        let scriptNonce = randomToken()
        let html = OIDCLoginPage.html(transaction: transaction, clientID: client.clientID, scopes: scopes.sorted().joined(separator: " "), nonce: scriptNonce)
        return HTTPResponsePayload(status: .ok, headers: [
            "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'nonce-\(scriptNonce)'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            "Set-Cookie": "__Host-oidc=\(transaction); Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300"
        ], body: Data(html.utf8))
    }

    private func loginBody(_ request: HTTPRequestAccumulator) throws -> (String, [String: Any]) {
        guard request.headers["Origin"].first == configuration.issuer,
              request.headers["Content-Type"].first?.lowercased().hasPrefix("application/json") == true,
              let body = try? jsonObject(from: request.body), let tx = body["transaction"] as? String,
              request.headers["Cookie"].joined(separator: ";").split(separator: ";").contains(where: {
                  $0.trimmingCharacters(in: .whitespaces) == "__Host-oidc=" + tx
              }), pending[hash(tx)] != nil else { throw OAuthFailure(code: "invalid_request") }
        return (hash(tx), body)
    }

    private func beginLogin(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let (tx, body) = try loginBody(request)
        guard var auth = pending.removeValue(forKey: tx), let username = body["username"] as? String else {
            throw OAuthFailure(code: "invalid_request")
        }
        // Reserve the transaction before suspension so concurrent requests cannot replace its challenge.
        guard let credential = try await store.credential(for: username), auth.expires > now() else {
            throw OAuthFailure(code: "access_denied")
        }
        auth.username = username
        auth.passkeyChallenge = randomBytes(count: 32)
        pending[tx] = auth
        return try json(["challenge": Base64URL.encode(auth.passkeyChallenge!), "rpId": service.relyingPartyID,
                         "allowCredentials": [["type": "public-key", "id": Base64URL.encode(credential.credentialID)]],
                         "userVerification": "required", "timeout": 60000])
    }

    private func completeLogin(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let (tx, body) = try loginBody(request)
        guard let auth = pending.removeValue(forKey: tx), let username = auth.username,
              let challenge = auth.passkeyChallenge, let object = body["credential"],
              let data = try? JSONSerialization.data(withJSONObject: object),
              let assertion = try? JSONDecoder().decode(AssertionCredential.self, from: data),
              let stored = try await store.credential(for: username) else { throw OAuthFailure(code: "access_denied") }
        // OIDC requires the exact configured origin and user verification, even if the legacy verifier permits omission.
        guard let clientData = try? Base64URL.decode(assertion.clientDataJSON),
              let clientObject = try? jsonObject(from: clientData), clientObject["origin"] as? String == configuration.issuer,
              clientObject["crossOrigin"] as? Bool != true,
              let authData = try? Base64URL.decode(assertion.authenticatorData), authData.count >= 37,
              authData[32] & 0x04 != 0, assertion.type == "public-key", auth.expires > now() else {
            throw OAuthFailure(code: "access_denied")
        }
        let result: AssertionResult
        do {
            result = try verifier.verifyAssertion(credential: assertion, storedCredential: stored, expectedChallenge: challenge, config: service)
        } catch { throw OAuthFailure(code: "access_denied") }
        try await store.updateSignCount(username: username, signCount: result.newSignCount)
        guard auth.expires > now() else { throw OAuthFailure(code: "access_denied") }
        let code = randomToken()
        codes[hash(code)] = Grant(authorization: auth, subject: Base64URL.encode(stored.userID), username: username,
            authTime: Int(now().timeIntervalSince1970), family: randomToken(), expires: now().addingTimeInterval(60))
        let url = try redirectURL(auth.redirectURI, values: ["code": code, "state": auth.state, "iss": configuration.issuer])
        return try json(["redirect": url])
    }

    private func token(_ request: HTTPRequestAccumulator) throws -> HTTPResponsePayload {
        let p = try form(request)
        guard request.headers["Authorization"].isEmpty, p["client_secret"] == nil,
              let clientID = p["client_id"], configuration.clients.contains(where: { $0.clientID == clientID }) else {
            throw OAuthFailure(code: "invalid_client")
        }
        switch p["grant_type"] {
        case "authorization_code":
            guard let code = p["code"], let grant = codes[hash(code)], grant.expires > now(),
                  grant.authorization.clientID == clientID, p["redirect_uri"] == grant.authorization.redirectURI,
                  let verifier = p["code_verifier"], Self.validVerifier(verifier),
                  Base64URL.encode(Data(verifier.utf8).sha256()) == grant.authorization.challenge else {
                throw OAuthFailure(code: "invalid_grant")
            }
            codes.removeValue(forKey: hash(code))
            return try issue(grant, refreshExpiry: now().addingTimeInterval(30 * 86400), includeNonce: true)
        case "refresh_token":
            guard let token = p["refresh_token"], let record = refresh[hash(token)], record.grant.expires > now(),
                  record.grant.authorization.clientID == clientID else { throw OAuthFailure(code: "invalid_grant") }
            if record.used || revoked.contains(record.grant.family) {
                revoked.insert(record.grant.family)
                throw OAuthFailure(code: "invalid_grant")
            }
            if let scope = p["scope"], Set(scope.split(separator: " ").map(String.init)) != record.grant.authorization.scope {
                throw OAuthFailure(code: "invalid_scope")
            }
            refresh[hash(token)]?.used = true
            return try issue(record.grant, refreshExpiry: record.grant.expires, includeNonce: false)
        default: throw OAuthFailure(code: "unsupported_grant_type")
        }
    }

    private func issue(_ grant: Grant, refreshExpiry: Date, includeNonce: Bool) throws -> HTTPResponsePayload {
        guard access.count + refresh.count < 50000 else { throw OAuthFailure(code: "temporarily_unavailable") }
        let timestamp = Int(now().timeIntervalSince1970)
        var claims: [String: Any] = ["iss": configuration.issuer, "sub": grant.subject,
            "aud": grant.authorization.clientID, "iat": timestamp, "exp": timestamp + 600, "auth_time": grant.authTime]
        if includeNonce, let nonce = grant.authorization.nonce { claims["nonce"] = nonce }
        let accessToken = randomToken()
        let idToken = try OIDCSigner(configuration: configuration).sign(claims)
        access[hash(accessToken)] = copy(grant, expires: now().addingTimeInterval(600))
        var body: [String: Any] = ["access_token": accessToken, "token_type": "Bearer", "expires_in": 600,
            "id_token": idToken, "scope": grant.authorization.scope.sorted().joined(separator: " ")]
        if grant.authorization.scope.contains("offline_access") {
            let refreshToken = randomToken()
            refresh[hash(refreshToken)] = RefreshRecord(grant: copy(grant, expires: refreshExpiry))
            body["refresh_token"] = refreshToken
        }
        return try json(body)
    }

    private func userInfo(_ request: HTTPRequestAccumulator) throws -> HTTPResponsePayload {
        guard let header = request.headers["Authorization"].first, header.lowercased().hasPrefix("bearer "),
              let grant = access[hash(String(header.dropFirst(7)))], grant.expires > now(), !revoked.contains(grant.family) else {
            throw OAuthFailure(code: "invalid_token")
        }
        var body = ["sub": grant.subject]
        if grant.authorization.scope.contains("profile") { body["preferred_username"] = grant.username }
        return try json(body)
    }

    private func revoke(_ request: HTTPRequestAccumulator) throws -> HTTPResponsePayload {
        let p = try form(request)
        guard let client = p["client_id"], configuration.clients.contains(where: { $0.clientID == client }),
              request.headers["Authorization"].isEmpty, p["client_secret"] == nil, let token = p["token"] else {
            throw OAuthFailure(code: "invalid_request")
        }
        let key = hash(token)
        if let grant = refresh[key]?.grant ?? access[key], grant.authorization.clientID == client { revoked.insert(grant.family) }
        return HTTPResponsePayload(status: .ok, headers: ["Cache-Control": "no-store"], body: Data())
    }

    private func copy(_ grant: Grant, expires: Date) -> Grant {
        Grant(authorization: grant.authorization, subject: grant.subject, username: grant.username,
              authTime: grant.authTime, family: grant.family, expires: expires)
    }

    private func cleanup() {
        let date = now()
        pending = pending.filter { $0.value.expires > date }
        codes = codes.filter { $0.value.expires > date }
        access = access.filter { $0.value.expires > date }
        refresh = refresh.filter { $0.value.grant.expires > date }
        let families = Set(access.values.map(\.family) + refresh.values.map { $0.grant.family })
        revoked.formIntersection(families)
    }

    private func form(_ request: HTTPRequestAccumulator) throws -> [String: String] {
        guard request.body.count <= 16384,
              request.headers["Content-Type"].first?.split(separator: ";").first?.lowercased() == "application/x-www-form-urlencoded",
              let string = String(data: request.body, encoding: .utf8) else { throw OAuthFailure(code: "invalid_request") }
        return try Self.parameters(string)
    }

    static func parameters(_ string: String) throws -> [String: String] {
        guard string.utf8.count <= 16384 else { throw OAuthFailure(code: "invalid_request") }
        var result: [String: String] = [:]
        for pair in string.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let name = String(parts[0]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  let value = String(parts[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  result[name] == nil else { throw OAuthFailure(code: "invalid_request") }
            result[name] = value
        }
        return result
    }

    static func validVerifier(_ value: String) -> Bool {
        (43...128).contains(value.utf8.count) && value.utf8.allSatisfy { byte in
            (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || [45, 46, 95, 126].contains(byte)
        }
    }

    static func validChallenge(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || [45, 95].contains(byte)
        } && (try? Base64URL.decode(value)).map { Base64URL.encode($0) == value } == true
    }

    private func randomToken() -> String { Base64URL.encode(randomBytes(count: 32)) }
    private func hash(_ token: String) -> String { Base64URL.encode(Data(token.utf8).sha256()) }

    private func json(_ body: [String: Any], status: HTTPResponseStatus = .ok) throws -> HTTPResponsePayload {
        HTTPResponsePayload(status: status, headers: ["Content-Type": "application/json", "Cache-Control": "no-store", "Pragma": "no-cache"],
                            body: try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]))
    }

    private func redirectURL(_ uri: String, values: [String: String?]) throws -> String {
        guard var components = URLComponents(string: uri) else { throw OAuthFailure(code: "invalid_request") }
        components.queryItems = (components.queryItems ?? []) + values.compactMap { key, value in value.map { URLQueryItem(name: key, value: $0) } }
        guard let url = components.string else { throw OAuthFailure(code: "invalid_request") }
        return url
    }

    private func redirectResponse(_ uri: String, values: [String: String?]) throws -> HTTPResponsePayload {
        HTTPResponsePayload(status: .found, headers: ["Location": try redirectURL(uri, values: values), "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"], body: Data())
    }
}
