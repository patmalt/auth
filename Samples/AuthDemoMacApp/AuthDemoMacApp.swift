#if os(macOS)
import SwiftUI
import AuthKit

@main
struct AuthDemoMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .frame(minWidth: 520, minHeight: 640)
        }
        .windowResizability(.contentSize)
    }
}
#endif
