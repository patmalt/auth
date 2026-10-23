#if os(macOS)
import Foundation

enum AppConfiguration {
    static let issuer = URL(string: configured("AUTH_DEMO_ISSUER", fallback: "https://auth.example.com"))!
    static let clientID = configured("AUTH_DEMO_CLIENT_ID", fallback: "auth-demo-macos")
    static let redirectURI = URL(string: configured("AUTH_DEMO_REDIRECT_URI", fallback: "com.patmalt.authdemo:/callback"))!
    private static func configured(_ key: String, fallback: String) -> String {
        let value = Bundle.main.object(forInfoDictionaryKey: key) as? String
        return value.flatMap { $0.isEmpty ? nil : $0 } ?? fallback
    }
}
#endif
