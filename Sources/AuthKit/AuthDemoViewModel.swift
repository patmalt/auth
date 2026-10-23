#if os(iOS) || os(macOS)
import Foundation
import Combine

@MainActor
public final class AuthDemoViewModel: ObservableObject {
    @Published public var statusMessage = "Ready"
    @Published public var isBusy = false
    private let client: OIDCClient
    public init(issuer: URL, clientID: String, redirectURI: URL) {
        client = OIDCClient(issuer: issuer, clientID: clientID, redirectURI: redirectURI)
    }
    public func authenticate() async { await run { self.statusMessage = "Signed in: " + (try await self.client.signIn()) } }
    public func refresh() async { await run { self.statusMessage = "Session restored: " + (try await self.client.refresh()) } }
    public func loadProfile() async {
        await run {
            let profile = try await self.client.profile()
            self.statusMessage = "Subject: \(profile.sub)\nUsername: \(profile.preferred_username ?? "Not shared")"
        }
    }
    public func signOut() async { await run { try await self.client.signOut(); self.statusMessage = "Signed out" } }
    private func run(_ action: () async throws -> Void) async {
        guard !isBusy else { return }
        isBusy = true; defer { isBusy = false }
        do { try await action() } catch { statusMessage = error.localizedDescription }
    }
}
#endif
