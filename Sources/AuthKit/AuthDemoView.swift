#if os(iOS) || os(macOS)
import SwiftUI

public struct AuthDemoView: View {
    @StateObject private var viewModel: AuthDemoViewModel

    public init(baseURL: URL, relyingPartyID: String, defaultUsername: String = "demo@example.com") {
        _viewModel = StateObject(
            wrappedValue: AuthDemoViewModel(
                baseURL: baseURL,
                relyingPartyID: relyingPartyID,
                defaultUsername: defaultUsername
            )
        )
    }

    public var body: some View {
        NavigationStack {
            Form {
                Section("User") {
                    usernameField
                }

                Section("Actions") {
                    Button("Create Passkey") {
                        Task { await viewModel.registerPasskey() }
                    }
                    .disabled(viewModel.isBusy || viewModel.username.isEmpty)

                    Button("Authenticate") {
                        Task { await viewModel.authenticate() }
                    }
                    .disabled(viewModel.isBusy || viewModel.username.isEmpty)

                    Button("Load /me") {
                        Task { await viewModel.loadProfile() }
                    }
                    .disabled(viewModel.isBusy || viewModel.accessToken == nil)
                }

                if let token = viewModel.accessToken {
                    Section("JWT") {
                        Text(token)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }

                Section("Status") {
                    Text(viewModel.statusMessage)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Auth Demo")
        }
    }

    @ViewBuilder
    private var usernameField: some View {
        #if os(iOS)
        TextField("Username", text: $viewModel.username)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        #elseif os(macOS)
        TextField("Username", text: $viewModel.username)
        #endif
    }
}
#endif
