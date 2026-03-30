#if os(macOS)
import Foundation

enum AppConfiguration {
    static let baseURL = configuredURL("AUTH_DEMO_BASE_URL") ?? URL(string: "https://auth.example.com")!
    static let relyingPartyID = configuredString("AUTH_DEMO_RP_ID") ?? "example.com"
    static let defaultUsername = configuredString("AUTH_DEMO_DEFAULT_USERNAME") ?? "demo@example.com"

    private static func configuredString(_ key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else {
            return nil
        }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func configuredURL(_ key: String) -> URL? {
        guard let value = configuredString(key) else {
            return nil
        }

        return URL(string: value)
    }
}
#endif
