#if os(iOS) || os(macOS)
import AuthenticationServices
import Foundation
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// Only system-browser presentation and its lifecycle require the main actor.
@MainActor
final class OIDCBrowserSession: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var browser: ASWebAuthenticationSession?
    private var continuation: CheckedContinuation<URL, Error>?

    func authenticate(url: URL, callbackURLScheme: String?) async throws -> URL {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackURLScheme) { url, error in
                    Task { @MainActor in
                        if let url { self.finish(.success(url)) }
                        else { self.finish(.failure(error ?? URLError(.cancelled))) }
                    }
                }
                browser = session
                session.presentationContextProvider = self
                session.prefersEphemeralWebBrowserSession = true
                if !session.start() { finish(.failure(URLError(.cannotLoadFromNetwork))) }
            }
        } onCancel: {
            Task { @MainActor in self.cancel() }
        }
    }

    private func cancel() {
        let session = browser
        finish(.failure(CancellationError()))
        session?.cancel()
    }

    /// Cancellation, start failure and the browser callback may race; complete exactly once.
    private func finish(_ result: Result<URL, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        browser = nil
        continuation.resume(with: result)
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(iOS)
        return UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap(\.windows).first { $0.isKeyWindow } ?? ASPresentationAnchor()
        #else
        return NSApplication.shared.windows.first { $0.isKeyWindow } ?? ASPresentationAnchor()
        #endif
    }
}
#endif
