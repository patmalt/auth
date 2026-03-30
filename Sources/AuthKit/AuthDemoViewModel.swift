#if os(iOS) || os(macOS)
import Foundation

@MainActor
public final class AuthDemoViewModel: ObservableObject {
    @Published public var username: String
    @Published public var statusMessage = "Ready"
    @Published public var accessToken: String?
    @Published public var isBusy = false

    private let api: DemoAPIClient
    private let passkeyProvider: any PasskeyProviding
    private let sessionStore = AuthSessionStore()

    public init(baseURL: URL, relyingPartyID: String, defaultUsername: String = "demo@example.com") {
        self.username = defaultUsername
        self.api = DemoAPIClient(baseURL: baseURL)
        self.passkeyProvider = PasskeyCoordinator(rpID: relyingPartyID)
    }

    init(
        baseURL: URL,
        relyingPartyID: String,
        defaultUsername: String = "demo@example.com",
        passkeyProvider: any PasskeyProviding
    ) {
        self.username = defaultUsername
        self.api = DemoAPIClient(baseURL: baseURL)
        self.passkeyProvider = passkeyProvider
    }

    public func registerPasskey() async {
        await runOperation("Creating passkey") { [self] in
            let options = try await self.api.beginRegistration(username: self.username)
            let result = try await self.passkeyProvider.register(options: options)
            try await self.api.completeRegistration(username: self.username, credential: result)
            self.statusMessage = "Passkey created and uploaded to the server."
        }
    }

    public func authenticate() async {
        await runOperation("Authenticating with passkey") { [self] in
            let options = try await self.api.beginAuthentication(username: self.username)
            let result = try await self.passkeyProvider.authenticate(options: options)
            let token = try await self.api.completeAuthentication(username: self.username, credential: result)
            await self.sessionStore.setAccessToken(token.accessToken)
            self.accessToken = token.accessToken
            self.statusMessage = "Authenticated. Token expires at \(token.expiresAt)."
        }
    }

    public func loadProfile() async {
        await runOperation("Calling protected endpoint") { [self] in
            let token = await self.sessionStore.currentAccessToken() ?? self.accessToken ?? ""
            let profile = try await self.api.me(token: token)
            self.statusMessage = "Authenticated subject: \(profile.subject)"
        }
    }

    private func runOperation(_ activity: String, action: @escaping () async throws -> Void) async {
        isBusy = true
        statusMessage = activity
        defer { isBusy = false }

        do {
            try await action()
        } catch {
            statusMessage = error.localizedDescription
        }
    }
}
#endif
