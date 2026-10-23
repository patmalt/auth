#if os(iOS) || os(macOS)
import SwiftUI

@MainActor
public struct AuthDemoView: View {
    @StateObject private var viewModel: AuthDemoViewModel
    public init(issuer: URL, clientID: String, redirectURI: URL) {
        _viewModel = StateObject(wrappedValue: AuthDemoViewModel(issuer: issuer, clientID: clientID, redirectURI: redirectURI))
    }
    public var body: some View {
        NavigationStack {
            Form {
                Section("OpenID Connect") {
                    Button("Sign in / Create account") { Task { await viewModel.authenticate() } }
                    Button("Restore / Refresh session") { Task { await viewModel.refresh() } }
                    Button("Load UserInfo") { Task { await viewModel.loadProfile() } }
                    Button("Sign out") { Task { await viewModel.signOut() } }
                }.disabled(viewModel.isBusy)
                Section("Status") { Text(viewModel.statusMessage).textSelection(.enabled) }
            }.navigationTitle("OIDC Auth Demo")
        }
    }
}
#endif
