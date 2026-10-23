#if os(macOS)
import SwiftUI
import AuthKit

struct RootView: View {
    var body: some View {
        AuthDemoView(issuer: AppConfiguration.issuer, clientID: AppConfiguration.clientID, redirectURI: AppConfiguration.redirectURI)
    }
}
#endif
