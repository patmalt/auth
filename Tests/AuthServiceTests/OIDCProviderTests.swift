import XCTest
import Foundation
import NIOHTTP1
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AuthService

private struct StubVerifier: WebAuthnVerifying {
    func parseAttestation(attestationObject: Data, clientDataJSON: Data, expectedChallenge: Data, config: ServiceConfiguration) throws -> AttestationResult {
        throw HTTPError.badRequest("Unused")
    }
    func verifyAssertion(credential: AssertionCredential, storedCredential: StoredCredential, expectedChallenge: Data, config: ServiceConfiguration) throws -> AssertionResult {
        let data = try jsonObject(from: Base64URL.decode(credential.clientDataJSON))
        guard data["challenge"] as? String == Base64URL.encode(expectedChallenge) else { throw HTTPError.badRequest("Challenge") }
        return AssertionResult(credentialID: storedCredential.credentialID, newSignCount: 1)
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date()
    func date() -> Date { lock.withLock { value } }
    func advance(_ seconds: TimeInterval) { lock.withLock { value = value.addingTimeInterval(seconds) } }
}

@MainActor
final class OIDCProviderTests: XCTestCase {
    let verifier = String(repeating: "a", count: 43)
    let redirect = "https://client.example/callback"

    private func provider(clock: TestClock = TestClock()) async throws -> OIDCProvider {
        let store = InMemoryCredentialStore()
        try await store.saveCredential(StoredCredential(credentialID: Data([1]), username: "alice", userID: Data([2]),
            publicKeyX963: Data(), signCount: 0))
        return OIDCProvider(configuration: configuration(), service: .fromEnvironment(), store: store, verifier: StubVerifier(), now: { clock.date() })
    }
    func configuration() -> OIDCConfiguration {
        OIDCConfiguration(issuer: "https://example.com", clients: [OIDCClient(clientID: "test", redirectURIs: [redirect])], signingKey: P256.Signing.PrivateKey())
    }
    func request(_ path: String, _ body: [String: String] = [:]) -> HTTPRequestAccumulator {
        var c = URLComponents()
        c.queryItems = body.map { URLQueryItem(name: $0.key, value: $0.value) }
        return HTTPRequestAccumulator(method: .POST, uri: path, headers: ["Content-Type": "application/x-www-form-urlencoded"], body: Data((c.percentEncodedQuery ?? "").utf8))
    }
    func object(_ response: HTTPResponsePayload?) throws -> [String: Any] {
        try jsonObject(from: XCTUnwrap(response).body)
    }
    func authorization(_ additional: [String: String] = [:]) -> HTTPRequestAccumulator {
        var p = ["client_id": "test", "redirect_uri": redirect, "response_type": "code", "scope": "openid profile offline_access",
            "state": "state value", "nonce": "nonce value", "code_challenge_method": "S256",
            "code_challenge": Base64URL.encode(Data(verifier.utf8).sha256())]
        p.merge(additional) { _, new in new }
        let form = request("/oauth/authorize", p)
        return HTTPRequestAccumulator(method: .GET, uri: "/oauth/authorize?" + String(data: form.body, encoding: .utf8)!)
    }
    func login(_ provider: OIDCProvider) async throws -> String {
        let initialResponse = await provider.respond(to: authorization())
        let response = try XCTUnwrap(initialResponse)
        XCTAssertEqual(response.status, .ok)
        let cookie = try XCTUnwrap(response.headers["Set-Cookie"]?.components(separatedBy: ";").first)
        let transaction = String(cookie.dropFirst("__Host-oidc=".count))
        func loginRequest(_ path: String, _ body: [String: Any]) throws -> HTTPRequestAccumulator {
            HTTPRequestAccumulator(method: .POST, uri: path, headers: ["Origin": "https://example.com", "Content-Type": "application/json", "Cookie": cookie],
                body: try JSONSerialization.data(withJSONObject: body.merging(["transaction": transaction]) { a, _ in a }))
        }
        let begin = try object(await provider.respond(to: loginRequest("/oauth/login/begin", ["username": "alice"])))
        let clientData = try JSONSerialization.data(withJSONObject: ["origin": "https://example.com", "challenge": try XCTUnwrap(begin["challenge"] as? String), "type": "webauthn.get"])
        let assertion = ["id": "AQ", "rawID": "AQ", "type": "public-key", "authenticatorData": Base64URL.encode(Data(repeating: 4, count: 37)),
            "clientDataJSON": Base64URL.encode(clientData), "signature": "AA"]
        let completeRequest = try loginRequest("/oauth/login/complete", ["credential": assertion])
        let complete = try object(await provider.respond(to: completeRequest))
        let url = try XCTUnwrap(URLComponents(string: try XCTUnwrap(complete["redirect"] as? String)))
        XCTAssertEqual(url.queryItems?.first(where: { $0.name == "state" })?.value, "state value")
        XCTAssertEqual(url.queryItems?.first(where: { $0.name == "iss" })?.value, "https://example.com")
        let replay = await provider.respond(to: completeRequest)
        XCTAssertEqual(replay?.status, .badRequest)
        return try XCTUnwrap(url.queryItems?.first(where: { $0.name == "code" })?.value)
    }

    func testAuthorizationCodePKCEAndRefreshReplay() async throws {
        let provider = try await provider()
        let code = try await login(provider)
        let base = ["grant_type": "authorization_code", "client_id": "test", "redirect_uri": redirect, "code": code, "code_verifier": verifier]
        var wrong = base; wrong["code_verifier"] = String(repeating: "b", count: 43)
        let rejected = await provider.respond(to: request("/oauth/token", wrong))
        XCTAssertEqual(try object(rejected)["error"] as? String, "invalid_grant")
        wrong = base; wrong["redirect_uri"] = "https://evil.example"
        let redirectRejected = await provider.respond(to: request("/oauth/token", wrong))
        XCTAssertEqual(redirectRejected?.status, .badRequest)
        let tokens = try object(await provider.respond(to: request("/oauth/token", base)))
        let id = try XCTUnwrap(tokens["id_token"] as? String).split(separator: ".")
        let claims = try jsonObject(from: Base64URL.decode(String(id[1])))
        XCTAssertEqual(claims["nonce"] as? String, "nonce value")
        XCTAssertEqual(claims["aud"] as? String, "test")
        XCTAssertEqual(claims["sub"] as? String, "Ag")
        let old = try XCTUnwrap(tokens["refresh_token"] as? String)
        let refreshRequest = request("/oauth/token", ["grant_type": "refresh_token", "client_id": "test", "refresh_token": old])
        let rotated = try object(await provider.respond(to: refreshRequest))
        XCTAssertNotEqual(rotated["refresh_token"] as? String, old)
        let replay = await provider.respond(to: refreshRequest)
        XCTAssertEqual(try object(replay)["error"] as? String, "invalid_grant")
        let user = await provider.respond(to: HTTPRequestAccumulator(uri: "/oauth/userinfo", headers: ["Authorization": "Bearer " + (rotated["access_token"] as! String)]))
        XCTAssertEqual(user?.status, .unauthorized)
        let rotatedRejected = await provider.respond(to: request("/oauth/token", ["grant_type": "refresh_token", "client_id": "test", "refresh_token": rotated["refresh_token"] as! String]))
        XCTAssertEqual(rotatedRejected?.status, .badRequest)
        let codeReplay = await provider.respond(to: request("/oauth/token", base))
        XCTAssertEqual(codeReplay?.status, .badRequest)
    }

    func testRejectsOpenRedirectAndDuplicateParameters() async throws {
        let provider = try await provider()
        let redirect = await provider.respond(to: authorization(["redirect_uri": "https://evil.example"]))
        XCTAssertEqual(redirect?.status, .badRequest)
        XCTAssertNil(redirect?.headers["Location"])
        var duplicate = authorization(); duplicate.uri += "&client_id=test"
        let rejected = await provider.respond(to: duplicate)
        XCTAssertEqual(rejected?.status, .badRequest)
        let unsupported = await provider.respond(to: authorization(["code_challenge_method": "plain"]))
        XCTAssertEqual(unsupported?.status, .found)
        XCTAssertTrue(unsupported?.headers["Location"]?.contains("error=invalid_request") == true)
        let none = await provider.respond(to: authorization(["prompt": "none"]))
        XCTAssertTrue(none?.headers["Location"]?.contains("login_required") == true)
    }

    func testLoginRequiresSameOriginAndCookie() async throws {
        let provider = try await provider()
        let response = await provider.respond(to: HTTPRequestAccumulator(method: .POST, uri: "/oauth/login/begin", headers: ["Origin": "https://evil.example", "Content-Type": "application/json"], body: Data("{}".utf8)))
        XCTAssertEqual(response?.status, .badRequest)
    }

    func testSigningAndJWKS() throws {
        let config = configuration()
        try config.validate()
        let signer = OIDCSigner(configuration: config)
        let token = try signer.sign(["sub": "alice"])
        let parts = token.split(separator: ".")
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Base64URL.decode(String(parts[2])))
        XCTAssertTrue(config.signingKey.publicKey.isValidSignature(signature, for: Data((String(parts[0]) + "." + String(parts[1])).utf8)))
        let raw = try Base64URL.decode(signer.jwk["x"]!) + Base64URL.decode(signer.jwk["y"]!)
        XCTAssertEqual(raw, config.signingKey.publicKey.rawRepresentation)
        XCTAssertNil(signer.jwk["d"])
    }

    func testCodeAndRefreshExpiration() async throws {
        let clock = TestClock()
        let provider = try await provider(clock: clock)
        let expiredCode = try await login(provider)
        clock.advance(61)
        let expired = await provider.respond(to: request("/oauth/token", ["grant_type": "authorization_code", "client_id": "test", "redirect_uri": redirect, "code": expiredCode, "code_verifier": verifier]))
        XCTAssertEqual(try object(expired)["error"] as? String, "invalid_grant")
        let code = try await login(provider)
        let tokens = try object(await provider.respond(to: request("/oauth/token", ["grant_type": "authorization_code", "client_id": "test", "redirect_uri": redirect, "code": code, "code_verifier": verifier])))
        clock.advance(30 * 86400 + 1)
        let refresh = await provider.respond(to: request("/oauth/token", ["grant_type": "refresh_token", "client_id": "test", "refresh_token": tokens["refresh_token"] as! String]))
        XCTAssertEqual(try object(refresh)["error"] as? String, "invalid_grant")
    }

    func testUserInfoAndRevocation() async throws {
        let provider = try await provider()
        let code = try await login(provider)
        let tokens = try object(await provider.respond(to: request("/oauth/token", ["grant_type": "authorization_code", "client_id": "test", "redirect_uri": redirect, "code": code, "code_verifier": verifier])))
        let token = try XCTUnwrap(tokens["access_token"] as? String)
        let userRequest = HTTPRequestAccumulator(uri: "/oauth/userinfo", headers: ["Authorization": "Bearer " + token])
        let user = try object(await provider.respond(to: userRequest))
        XCTAssertEqual(user["sub"] as? String, "Ag")
        XCTAssertEqual(user["preferred_username"] as? String, "alice")
        let revoked = await provider.respond(to: request("/oauth/revoke", ["client_id": "test", "token": token]))
        XCTAssertEqual(revoked?.status, .ok)
        let rejected = await provider.respond(to: userRequest)
        XCTAssertEqual(rejected?.status, .unauthorized)
    }

    func testPKCEParsing() throws {
        XCTAssertTrue(OIDCProvider.validVerifier(verifier))
        XCTAssertFalse(OIDCProvider.validVerifier("short"))
        XCTAssertFalse(OIDCProvider.validVerifier(String(repeating: "+", count: 43)))
        XCTAssertThrowsError(try OIDCProvider.parameters("client_id=a&client_id=b"))
        XCTAssertEqual(try OIDCProvider.parameters("state=a%2Bb+c")["state"], "a+b c")
    }
}
