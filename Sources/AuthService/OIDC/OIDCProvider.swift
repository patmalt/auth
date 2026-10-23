import Foundation
import NIOHTTP1

private struct OAuthFailure: Error {
    let code: String
}

private struct Authorization: Codable, Sendable {
    let clientID: String
    let redirectURI: String
    let scope: Set<String>
    let state: String?
    let nonce: String?
    let challenge: String
    let expires: Date
    var username: String?
    var passkeyChallenge: Data?
    var registrationUserID: Data?
}

private struct Grant: Codable, Sendable {
    let authorization: Authorization
    let subject: String
    let username: String
    let authTime: Int
    let family: String
    let expires: Date
}

private struct RefreshRecord: Codable, Sendable {
    let grant: Grant
    var used: Bool = false
}

private struct TokenFamily: Codable, Sendable { var revoked = false }

/// Security state is shared through GrantStoring; actor isolation is not relied on for redemption.
actor OIDCProvider {
    private let configuration: OIDCConfiguration
    private let service: ServiceConfiguration
    private let store: any CredentialStoring
    private let verifier: any WebAuthnVerifying
    private let grants: any GrantStoring
    private let now: @Sendable () -> Date

    init(configuration: OIDCConfiguration, service: ServiceConfiguration, store: any CredentialStoring,
         verifier: any WebAuthnVerifying = WebAuthnVerifier(), grants: any GrantStoring = InMemoryGrantStore(), now: @escaping @Sendable () -> Date = { Date() }) {
        self.configuration = configuration
        self.service = service
        self.store = store
        self.verifier = verifier
        self.now = now
        self.grants = grants
    }

    func respond(to request: HTTPRequestAccumulator) async -> HTTPResponsePayload? {
        let path = String(request.uri.split(separator: "?", maxSplits: 1).first ?? "/")
        let routes = ["/.well-known/openid-configuration", "/oauth/jwks", "/oauth/authorize", "/oauth/login/begin",
                      "/oauth/login/complete", "/oauth/register/complete", "/oauth/token", "/oauth/userinfo", "/oauth/revoke"]
        guard routes.contains(path) else { return nil }
        do {
            switch (request.method, path) {
            case (.GET, "/.well-known/openid-configuration"):
                return try json(discovery())
            case (.GET, "/oauth/jwks"):
                return try json(["keys": [OIDCSigner(configuration: configuration).jwk]])
            case (.GET, "/oauth/authorize"):
                return try await authorize(request)
            case (.POST, "/oauth/login/begin"):
                return try await beginLogin(request)
            case (.POST, "/oauth/login/complete"):
                return try await completeLogin(request)
            case (.POST, "/oauth/register/complete"):
                return try await completeRegistration(request)
            case (.POST, "/oauth/token"):
                return try await token(request)
            case (.GET, "/oauth/userinfo"), (.POST, "/oauth/userinfo"):
                return try await userInfo(request)
            case (.POST, "/oauth/revoke"):
                return try await revoke(request)
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

    private func authorize(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let parts = request.uri.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let p = try Self.parameters(parts.count == 2 ? String(parts[1]) : "")
        // Never redirect before both client and exact redirect URI have been validated.
        guard let client = configuration.clients.first(where: { $0.clientID == p["client_id"] }),
              let redirect = p["redirect_uri"], client.redirectURIs.contains(redirect) else {
            throw OAuthFailure(code: "invalid_request")
        }
        func fail(_ code: String) throws -> HTTPResponsePayload {
            try redirectResponse(redirect, values: ["error": code, "state": p["state"], "iss": configuration.issuer])
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
        let transaction = randomToken()
        let auth = Authorization(clientID: client.clientID, redirectURI: redirect, scope: scopes,
            state: p["state"], nonce: p["nonce"], challenge: challenge, expires: now().addingTimeInterval(300))
        let record = try GrantRecord(key: "login#" + hash(transaction), value: auth, expires: auth.expires)
        guard try await grants.transact(expected: [], putting: [record], deleting: [], now: now()) else {
            throw OAuthFailure(code: "temporarily_unavailable")
        }
        let scriptNonce = randomToken()
        let html = OIDCLoginPage.html(transaction: transaction, clientID: client.clientID, scopes: scopes.sorted().joined(separator: " "), nonce: scriptNonce)
        return HTTPResponsePayload(status: .ok, headers: [
            "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'nonce-\(scriptNonce)'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            "Set-Cookie": "__Host-oidc=\(transaction); Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300"
        ], body: Data(html.utf8))
    }

    private func loginBody(_ request: HTTPRequestAccumulator) async throws -> (GrantRecord, [String: Any]) {
        guard request.body.count <= 32768, request.headers["Origin"].first == configuration.issuer,
              request.headers["Content-Type"].first?.lowercased().hasPrefix("application/json") == true,
              let body = try? jsonObject(from: request.body), let tx = body["transaction"] as? String,
              request.headers["Cookie"].joined(separator: ";").split(separator: ";").contains(where: {
                  $0.trimmingCharacters(in: .whitespaces) == "__Host-oidc=" + tx
              }), let record = try await grants.get("login#" + hash(tx), now: now()) else {
            throw OAuthFailure(code: "invalid_request")
        }
        return (record, body)
    }

    private func beginLogin(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let (record, body) = try await loginBody(request)
        var auth = try record.decode(Authorization.self)
        guard auth.passkeyChallenge == nil, let username = body["username"] as? String, !username.isEmpty else {
            throw OAuthFailure(code: "invalid_request")
        }
        let existing = try await store.credential(for: username)
        let registering = body["mode"] as? String == "register"
        if registering && existing != nil { throw OAuthFailure(code: "access_denied") }
        if !registering && existing == nil { throw OAuthFailure(code: "access_denied") }
        auth.username = username
        let challenge = randomBytes(count: 32)
        auth.passkeyChallenge = challenge
        if registering { auth.registrationUserID = randomBytes(count: 32) }
        let replacement = try GrantRecord(key: record.key, value: auth, expires: auth.expires)
        guard try await grants.transact(expected: [record], putting: [replacement], deleting: [], now: now()) else {
            throw OAuthFailure(code: "invalid_request")
        }
        if let userID = auth.registrationUserID {
            return try json(["challenge": Base64URL.encode(challenge),
                "rp": ["id": service.relyingPartyID, "name": service.relyingPartyName],
                "user": ["id": Base64URL.encode(userID), "name": username, "displayName": username],
                "pubKeyCredParams": [["type": "public-key", "alg": -7]], "attestation": "none",
                "authenticatorSelection": ["userVerification": "required"], "timeout": 60000])
        }
        return try json(["challenge": Base64URL.encode(challenge), "rpId": service.relyingPartyID,
            "allowCredentials": [["type": "public-key", "id": Base64URL.encode(existing!.credentialID)]],
            "userVerification": "required", "timeout": 60000])
    }

    private func consumeLogin(_ record: GrantRecord) async throws -> Authorization {
        guard try await grants.transact(expected: [record], putting: [], deleting: [record.key], now: now()) else {
            throw OAuthFailure(code: "invalid_request")
        }
        return try record.decode(Authorization.self)
    }

    private func validClientData(_ encoded: String, type: String) -> Bool {
        guard let data = try? Base64URL.decode(encoded), let object = try? jsonObject(from: data) else { return false }
        return object["origin"] as? String == configuration.issuer && object["type"] as? String == type && object["crossOrigin"] as? Bool != true
    }

    private func completeLogin(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let (record, body) = try await loginBody(request)
        let auth = try await consumeLogin(record)
        guard auth.registrationUserID == nil, let username = auth.username, let challenge = auth.passkeyChallenge,
              let object = body["credential"], let data = try? JSONSerialization.data(withJSONObject: object),
              let assertion = try? JSONDecoder().decode(AssertionCredential.self, from: data),
              let stored = try await store.credential(for: username),
              assertion.id == assertion.rawID, assertion.rawID == Base64URL.encode(stored.credentialID),
              assertion.userHandle == nil || assertion.userHandle == Base64URL.encode(stored.userID),
              validClientData(assertion.clientDataJSON, type: "webauthn.get"),
              let authData = try? Base64URL.decode(assertion.authenticatorData), authData.count >= 37,
              authData[32] & 0x04 != 0, assertion.type == "public-key" else { throw OAuthFailure(code: "access_denied") }
        let result: AssertionResult
        do {
            result = try verifier.verifyAssertion(credential: assertion, storedCredential: stored, expectedChallenge: challenge, config: service)
        } catch { throw OAuthFailure(code: "access_denied") }
        try await store.updateSignCount(username: username, signCount: result.newSignCount)
        return try await finishAuthorization(auth, credential: stored)
    }

    private func completeRegistration(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let (record, body) = try await loginBody(request)
        let auth = try await consumeLogin(record)
        guard let username = auth.username, let challenge = auth.passkeyChallenge, let userID = auth.registrationUserID,
              let object = body["credential"], let data = try? JSONSerialization.data(withJSONObject: object),
              let credential = try? JSONDecoder().decode(RegistrationCredential.self, from: data), credential.type == "public-key",
              validClientData(credential.clientDataJSON, type: "webauthn.create") else { throw OAuthFailure(code: "access_denied") }
        let result: AttestationResult
        do {
            let attestation = try Base64URL.decode(credential.attestationObject)
            var reader = CBORReader(data: attestation)
            let map = try reader.readValue().mapValue()
            guard let bytes = try map[.text("authData")]?.byteStringValue(), bytes.count >= 37, bytes[32] & 0x04 != 0 else {
                throw OAuthFailure(code: "access_denied")
            }
            result = try verifier.parseAttestation(attestationObject: attestation,
                clientDataJSON: Base64URL.decode(credential.clientDataJSON), expectedChallenge: challenge, config: service)
            guard credential.rawID == Base64URL.encode(result.credentialID), credential.id == credential.rawID else {
                throw OAuthFailure(code: "access_denied")
            }
        } catch { throw OAuthFailure(code: "access_denied") }
        let stored = StoredCredential(credentialID: result.credentialID, username: username, userID: userID,
            publicKeyX963: result.publicKeyX963, signCount: result.signCount)
        try await store.saveCredential(stored)
        return try await finishAuthorization(auth, credential: stored)
    }

    private func finishAuthorization(_ auth: Authorization, credential: StoredCredential) async throws -> HTTPResponsePayload {
        guard auth.expires > now() else { throw OAuthFailure(code: "access_denied") }
        let code = randomToken()
        let grant = Grant(authorization: auth, subject: Base64URL.encode(credential.userID), username: credential.username,
            authTime: Int(now().timeIntervalSince1970), family: randomToken(), expires: now().addingTimeInterval(60))
        let record = try GrantRecord(key: "code#" + hash(code), value: grant, expires: grant.expires)
        guard try await grants.transact(expected: [], putting: [record], deleting: [], now: now()) else {
            throw OAuthFailure(code: "temporarily_unavailable")
        }
        return try json(["redirect": redirectURL(auth.redirectURI, values: ["code": code, "state": auth.state, "iss": configuration.issuer])])
    }

    private func token(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let p = try form(request)
        guard request.headers["Authorization"].isEmpty, p["client_secret"] == nil,
              let clientID = p["client_id"], configuration.clients.contains(where: { $0.clientID == clientID }) else {
            throw OAuthFailure(code: "invalid_client")
        }
        switch p["grant_type"] {
        case "authorization_code":
            guard let code = p["code"], let record = try await grants.get("code#" + hash(code), now: now()) else {
                throw OAuthFailure(code: "invalid_grant")
            }
            let grant = try record.decode(Grant.self)
            guard grant.authorization.clientID == clientID, p["redirect_uri"] == grant.authorization.redirectURI,
                  let verifier = p["code_verifier"], Self.validVerifier(verifier),
                  Base64URL.encode(Data(verifier.utf8).sha256()) == grant.authorization.challenge else {
                throw OAuthFailure(code: "invalid_grant")
            }
            return try await issue(grant, consumed: record, family: nil, refreshExpiry: now().addingTimeInterval(30 * 86400), includeNonce: true)
        case "refresh_token":
            guard let token = p["refresh_token"], let record = try await grants.get("refresh#" + hash(token), now: now()) else {
                throw OAuthFailure(code: "invalid_grant")
            }
            let refresh = try record.decode(RefreshRecord.self)
            guard refresh.grant.authorization.clientID == clientID else { throw OAuthFailure(code: "invalid_grant") }
            guard let family = try await grants.get("family#" + refresh.grant.family, now: now()) else { throw OAuthFailure(code: "invalid_grant") }
            let familyState = try family.decode(TokenFamily.self)
            if refresh.used || familyState.revoked {
                try await revokeFamily(refresh.grant.family)
                throw OAuthFailure(code: "invalid_grant")
            }
            if let scope = p["scope"], Set(scope.split(separator: " ").map(String.init)) != refresh.grant.authorization.scope {
                throw OAuthFailure(code: "invalid_scope")
            }
            return try await issue(refresh.grant, consumed: record, family: family, refreshExpiry: refresh.grant.expires, includeNonce: false)
        default: throw OAuthFailure(code: "unsupported_grant_type")
        }
    }

    private func issue(_ grant: Grant, consumed: GrantRecord, family: GrantRecord?, refreshExpiry: Date, includeNonce: Bool) async throws -> HTTPResponsePayload {
        let timestamp = Int(now().timeIntervalSince1970)
        var claims: [String: Any] = ["iss": configuration.issuer, "sub": grant.subject,
            "aud": grant.authorization.clientID, "iat": timestamp, "exp": timestamp + 600, "auth_time": grant.authTime]
        if includeNonce, let nonce = grant.authorization.nonce { claims["nonce"] = nonce }
        let accessToken = randomToken()
        let idToken = try OIDCSigner(configuration: configuration).sign(claims)
        let familyExpiry = family?.expires ?? refreshExpiry
        var writes = [try GrantRecord(key: "access#" + hash(accessToken), value: copy(grant, expires: now().addingTimeInterval(600)), expires: now().addingTimeInterval(600)),
            try GrantRecord(key: "family#" + grant.family, value: TokenFamily(), expires: familyExpiry)]
        var body: [String: Any] = ["access_token": accessToken, "token_type": "Bearer", "expires_in": 600,
            "id_token": idToken, "scope": grant.authorization.scope.sorted().joined(separator: " ")]
        if grant.authorization.scope.contains("offline_access") {
            let refreshToken = randomToken()
            writes.append(try GrantRecord(key: "refresh#" + hash(refreshToken), value: RefreshRecord(grant: copy(grant, expires: refreshExpiry)), expires: refreshExpiry))
            body["refresh_token"] = refreshToken
        }
        if family != nil {
            writes.append(try GrantRecord(key: consumed.key, value: RefreshRecord(grant: grant, used: true), expires: consumed.expires))
        }
        let expected = [consumed] + (family.map { [$0] } ?? [])
        guard try await grants.transact(expected: expected, putting: writes, deleting: family == nil ? [consumed.key] : [], now: now()) else {
            // A competing refresh may have consumed the old token. Revocation is shared and survives restart.
            if family != nil { try await revokeFamily(grant.family) }
            throw OAuthFailure(code: "invalid_grant")
        }
        return try json(body)
    }

    private func userInfo(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        guard let header = request.headers["Authorization"].first, header.lowercased().hasPrefix("bearer "),
              let record = try await grants.get("access#" + hash(String(header.dropFirst(7))), now: now()) else {
            throw OAuthFailure(code: "invalid_token")
        }
        let grant = try record.decode(Grant.self)
        guard let family = try await grants.get("family#" + grant.family, now: now()),
              !(try family.decode(TokenFamily.self)).revoked else { throw OAuthFailure(code: "invalid_token") }
        var body = ["sub": grant.subject]
        if grant.authorization.scope.contains("profile") { body["preferred_username"] = grant.username }
        return try json(body)
    }

    private func revoke(_ request: HTTPRequestAccumulator) async throws -> HTTPResponsePayload {
        let p = try form(request)
        guard let client = p["client_id"], configuration.clients.contains(where: { $0.clientID == client }),
              request.headers["Authorization"].isEmpty, p["client_secret"] == nil, let token = p["token"] else {
            throw OAuthFailure(code: "invalid_request")
        }
        if let record = try await grants.get("refresh#" + hash(token), now: now()) {
            let grant = try record.decode(RefreshRecord.self).grant
            if grant.authorization.clientID == client { try await revokeFamily(grant.family) }
        } else if let record = try await grants.get("access#" + hash(token), now: now()) {
            let grant = try record.decode(Grant.self)
            if grant.authorization.clientID == client { try await revokeFamily(grant.family) }
        }
        return HTTPResponsePayload(status: .ok, headers: ["Cache-Control": "no-store"], body: Data())
    }

    private func revokeFamily(_ key: String) async throws {
        for _ in 0..<8 {
            guard let record = try await grants.get("family#" + key, now: now()) else { return }
            if try record.decode(TokenFamily.self).revoked { return }
            let revoked = try GrantRecord(key: record.key, value: TokenFamily(revoked: true), expires: record.expires)
            if try await grants.transact(expected: [record], putting: [revoked], deleting: [], now: now()) { return }
        }
        throw OAuthFailure(code: "temporarily_unavailable")
    }

    private func copy(_ grant: Grant, expires: Date) -> Grant {
        Grant(authorization: grant.authorization, subject: grant.subject, username: grant.username,
              authTime: grant.authTime, family: grant.family, expires: expires)
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
