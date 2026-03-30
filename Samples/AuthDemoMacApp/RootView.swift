#if os(macOS)
import SwiftUI
import AuthKit

struct RootView: View {
    var body: some View {
        AuthDemoView(
            baseURL: AppConfiguration.baseURL,
            relyingPartyID: AppConfiguration.relyingPartyID,
            defaultUsername: AppConfiguration.defaultUsername
        )
    }
}
#endif
