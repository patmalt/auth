#if os(iOS) || os(macOS)
import AuthenticationServices
import Foundation
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

protocol PasskeyProviding: Actor {
    func register(options: RegisterBeginResponseDTO) async throws -> RegistrationCredentialDTO
    func authenticate(options: AuthenticateBeginResponseDTO) async throws -> AssertionCredentialDTO
}

actor PasskeyCoordinator: PasskeyProviding {
    private let rpID: String

    init(rpID: String) {
        self.rpID = rpID
    }

    func register(options: RegisterBeginResponseDTO) async throws -> RegistrationCredentialDTO {
        let bridge = await MainActor.run { AuthorizationControllerBridge(rpID: self.rpID) }
        return try await bridge.register(options: options)
    }

    func authenticate(options: AuthenticateBeginResponseDTO) async throws -> AssertionCredentialDTO {
        let bridge = await MainActor.run { AuthorizationControllerBridge(rpID: self.rpID) }
        return try await bridge.authenticate(options: options)
    }
}

@MainActor
private final class AuthorizationControllerBridge: NSObject {
    private let provider: ASAuthorizationPlatformPublicKeyCredentialProvider
    private var continuation: CheckedContinuation<AuthorizationOutcome, Error>?

    init(rpID: String) {
        self.provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
    }

    func register(options: RegisterBeginResponseDTO) async throws -> RegistrationCredentialDTO {
        try validatePasskeyEnvironment()
        let challenge = try Data(base64URLEncoded: options.challenge)
        let userID = try Data(base64URLEncoded: options.user.id)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: options.user.name,
            userID: userID
        )
        let result = try await performAuthorization(request: request)
        guard case .registration(let registration) = result else {
            throw NSError(domain: "PasskeyCoordinator", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unexpected authorization result"])
        }
        return RegistrationCredentialDTO(
            id: registration.credentialID.base64URLEncodedString(),
            rawID: registration.credentialID.base64URLEncodedString(),
            type: "public-key",
            attestationObject: registration.rawAttestationObject?.base64URLEncodedString() ?? "",
            clientDataJSON: registration.rawClientDataJSON.base64URLEncodedString()
        )
    }

    func authenticate(options: AuthenticateBeginResponseDTO) async throws -> AssertionCredentialDTO {
        try validatePasskeyEnvironment()
        let challenge = try Data(base64URLEncoded: options.challenge)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        request.allowedCredentials = options.allowCredentials.compactMap {
            try? ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: Data(base64URLEncoded: $0.id))
        }
        let result = try await performAuthorization(request: request)
        guard case .assertion(let assertion) = result else {
            throw NSError(domain: "PasskeyCoordinator", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unexpected authorization result"])
        }
        return AssertionCredentialDTO(
            id: assertion.credentialID.base64URLEncodedString(),
            rawID: assertion.credentialID.base64URLEncodedString(),
            type: "public-key",
            authenticatorData: assertion.rawAuthenticatorData.base64URLEncodedString(),
            clientDataJSON: assertion.rawClientDataJSON.base64URLEncodedString(),
            signature: assertion.signature.base64URLEncodedString(),
            userHandle: assertion.userID?.base64URLEncodedString()
        )
    }

    private func validatePasskeyEnvironment() throws {
        #if os(macOS)
        let bundle = Bundle.main
        let hasBundleIdentifier = bundle.bundleIdentifier?.isEmpty == false
        let isBundledApp = bundle.bundleURL.pathExtension == "app"

        guard hasBundleIdentifier && isBundledApp else {
            throw NSError(
                domain: "PasskeyCoordinator",
                code: -3,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "This process does not have an app identifier. On macOS, passkeys require launching the signed app bundle from AuthDemoMacApp.xcodeproj, not `swift run AuthDemoMacApp`."
                ]
            )
        }
        #endif
    }

    private func performAuthorization(request: ASAuthorizationRequest) async throws -> AuthorizationOutcome {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }
}

extension AuthorizationControllerBridge: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            continuation?.resume(returning: .registration(registration))
        } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            continuation?.resume(returning: .assertion(assertion))
        } else {
            continuation?.resume(throwing: NSError(domain: "PasskeyCoordinator", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unsupported authorization credential"]))
        }
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

extension AuthorizationControllerBridge: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        #if os(iOS)
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
        #elseif os(macOS)
        NSApplication.shared.windows.first { $0.isKeyWindow } ?? NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #endif
    }
}

private enum AuthorizationOutcome {
    case registration(ASAuthorizationPlatformPublicKeyCredentialRegistration)
    case assertion(ASAuthorizationPlatformPublicKeyCredentialAssertion)
}

private extension Data {
    init(base64URLEncoded string: String) throws {
        let padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .padding(toLength: ((string.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: padded) else {
            throw NSError(domain: "PasskeyCoordinator", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid base64url string"])
        }
        self = data
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
#endif
