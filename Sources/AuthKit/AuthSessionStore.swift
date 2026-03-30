#if os(iOS) || os(macOS)
import Foundation

actor AuthSessionStore {
    private var accessToken: String?

    func setAccessToken(_ token: String?) {
        self.accessToken = token
    }

    func currentAccessToken() -> String? {
        accessToken
    }
}
#endif
