#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct AttestationResult {
    let credentialID: Data
    let publicKeyX963: Data
    let signCount: UInt32
}

struct AssertionResult {
    let credentialID: Data
    let newSignCount: UInt32
}

protocol WebAuthnVerifying: Sendable {
    func parseAttestation(
        attestationObject: Data,
        clientDataJSON: Data,
        expectedChallenge: Data,
        config: ServiceConfiguration
    ) throws -> AttestationResult

    func verifyAssertion(
        credential: AssertionCredential,
        storedCredential: StoredCredential,
        expectedChallenge: Data,
        config: ServiceConfiguration
    ) throws -> AssertionResult
}

struct WebAuthnVerifier: WebAuthnVerifying {
    func parseAttestation(
        attestationObject: Data,
        clientDataJSON: Data,
        expectedChallenge: Data,
        config: ServiceConfiguration
    ) throws -> AttestationResult {
        let clientData = try parseWebAuthnClientData(clientDataJSON)
        guard clientData.type == "webauthn.create" else {
            throw HTTPError.badRequest("Expected webauthn.create ceremony")
        }
        guard clientData.challenge == Base64URL.encode(expectedChallenge) else {
            throw HTTPError.badRequest("Registration challenge mismatch")
        }
        if let origin = clientData.origin, origin != config.origin {
            throw HTTPError.badRequest("Unexpected origin \(origin)")
        }

        var reader = CBORReader(data: attestationObject)
        let topLevel = try reader.readValue()
        let map = try topLevel.mapValue()
        guard let authDataValue = map[.text("authData")] else {
            throw HTTPError.badRequest("Attestation object missing authData")
        }
        let authData = try authDataValue.byteStringValue()
        return try parseAttestedCredentialData(authData: authData, rpID: config.relyingPartyID)
    }

    func verifyAssertion(
        credential: AssertionCredential,
        storedCredential: StoredCredential,
        expectedChallenge: Data,
        config: ServiceConfiguration
    ) throws -> AssertionResult {
        let authenticatorData = try Base64URL.decode(credential.authenticatorData)
        let clientDataJSON = try Base64URL.decode(credential.clientDataJSON)
        let signature = try Base64URL.decode(credential.signature)
        let clientData = try parseWebAuthnClientData(clientDataJSON)

        guard clientData.type == "webauthn.get" else {
            throw HTTPError.badRequest("Expected webauthn.get ceremony")
        }
        guard clientData.challenge == Base64URL.encode(expectedChallenge) else {
            throw HTTPError.badRequest("Authentication challenge mismatch")
        }
        if let origin = clientData.origin, origin != config.origin {
            throw HTTPError.badRequest("Unexpected origin \(origin)")
        }

        let parsed = try parseAuthenticatorData(authenticatorData, rpID: config.relyingPartyID)
        guard credential.rawID == Base64URL.encode(storedCredential.credentialID) || credential.id == Base64URL.encode(storedCredential.credentialID) else {
            throw HTTPError.unauthorized("Credential does not match registered passkey")
        }
        guard parsed.signCount >= storedCredential.signCount else {
            throw HTTPError.unauthorized("Authenticator sign count regressed")
        }

        let signedPayload = authenticatorData + clientDataJSON.sha256()
        let publicKey = try P256.Signing.PublicKey(x963Representation: storedCredential.publicKeyX963)
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        guard publicKey.isValidSignature(ecdsaSignature, for: signedPayload) else {
            throw HTTPError.unauthorized("Assertion signature verification failed")
        }

        return AssertionResult(
            credentialID: storedCredential.credentialID,
            newSignCount: parsed.signCount
        )
    }

    private func parseAttestedCredentialData(authData: Data, rpID: String) throws -> AttestationResult {
        let parsed = try parseAuthenticatorData(authData, rpID: rpID, requireAttestedCredentialData: true)
        guard let attested = parsed.attestedCredentialData else {
            throw HTTPError.badRequest("Attested credential data missing")
        }
        return AttestationResult(
            credentialID: attested.credentialID,
            publicKeyX963: try parseCOSEPublicKey(attested.credentialPublicKey),
            signCount: parsed.signCount
        )
    }

    private func parseCOSEPublicKey(_ data: Data) throws -> Data {
        var reader = CBORReader(data: data)
        let coseValue = try reader.readValue()
        let map = try coseValue.mapValue()
        guard let keyType = try map[.unsigned(1)]?.intValue(),
              let algorithm = try map[.unsigned(3)]?.intValue(),
              let curve = try map[.negative(-1)]?.intValue() else {
            throw HTTPError.badRequest("COSE public key is missing required fields")
        }
        guard keyType == 2, algorithm == -7, curve == 1 else {
            throw HTTPError.badRequest("Unsupported COSE key")
        }
        guard let x = try map[.negative(-2)]?.byteStringValue(),
              let y = try map[.negative(-3)]?.byteStringValue() else {
            throw HTTPError.badRequest("COSE public key is incomplete")
        }

        var x963 = Data([0x04])
        x963.append(x)
        x963.append(y)
        return x963
    }

    private func parseAuthenticatorData(
        _ data: Data,
        rpID: String,
        requireAttestedCredentialData: Bool = false
    ) throws -> ParsedAuthenticatorData {
        guard data.count >= 37 else {
            throw HTTPError.badRequest("Authenticator data too short")
        }

        let rpIDHash = data.prefix(32)
        let expectedHash = Data(SHA256.hash(data: Data(rpID.utf8)))
        guard rpIDHash == expectedHash else {
            throw HTTPError.badRequest("RP ID hash mismatch")
        }

        let flags = data[32]
        guard (flags & 0x01) != 0 else {
            throw HTTPError.unauthorized("User presence flag not set")
        }
        let signCount = try data.uint32BE(at: 33)

        let hasAttestedCredentialData = (flags & 0x40) != 0
        if requireAttestedCredentialData && !hasAttestedCredentialData {
            throw HTTPError.badRequest("Attested credential data flag not set")
        }

        var attestedCredentialData: ParsedAttestedCredentialData?
        if hasAttestedCredentialData {
            let credentialStart = 37
            guard data.count >= credentialStart + 18 else {
                throw HTTPError.badRequest("Authenticator attested data is incomplete")
            }
            let credentialIDLength = try data.uint16BE(at: credentialStart + 16)
            let credentialIDStart = credentialStart + 18
            let credentialIDEnd = credentialIDStart + Int(credentialIDLength)
            guard data.count >= credentialIDEnd else {
                throw HTTPError.badRequest("Credential ID overruns authenticator data")
            }

            let credentialID = Data(data[credentialIDStart..<credentialIDEnd])
            var reader = CBORReader(data: Data(data[credentialIDEnd...]))
            let cborStart = reader.index
            _ = try reader.readValue()
            let consumedBytes = reader.index - cborStart
            let publicKey = Data(data[credentialIDEnd..<(credentialIDEnd + consumedBytes)])

            attestedCredentialData = ParsedAttestedCredentialData(
                credentialID: credentialID,
                credentialPublicKey: publicKey
            )
        }

        return ParsedAuthenticatorData(signCount: signCount, attestedCredentialData: attestedCredentialData)
    }
}

private struct ParsedAuthenticatorData {
    let signCount: UInt32
    let attestedCredentialData: ParsedAttestedCredentialData?
}

private struct ParsedAttestedCredentialData {
    let credentialID: Data
    let credentialPublicKey: Data
}
