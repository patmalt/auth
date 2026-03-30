#if canImport(CryptoKit)
import CryptoKit
import Security
#else
import Crypto
#endif
import Foundation

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ string: String) throws -> Data {
        let padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .padding(
                toLength: ((string.count + 3) / 4) * 4,
                withPad: "=",
                startingAt: 0
            )

        guard let data = Data(base64Encoded: padded) else {
            throw HTTPError.badRequest("Invalid base64url payload")
        }
        return data
    }
}

extension Data {
    func sha256() -> Data {
        Data(SHA256.hash(data: self))
    }

    func hex() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    func uint16BE(at offset: Int) throws -> UInt16 {
        guard offset + 2 <= count else {
            throw HTTPError.badRequest("Byte range overflow")
        }
        return (UInt16(self[offset]) << 8) | UInt16(self[offset + 1])
    }

    func uint32BE(at offset: Int) throws -> UInt32 {
        guard offset + 4 <= count else {
            throw HTTPError.badRequest("Byte range overflow")
        }
        return (UInt32(self[offset]) << 24)
            | (UInt32(self[offset + 1]) << 16)
            | (UInt32(self[offset + 2]) << 8)
            | UInt32(self[offset + 3])
    }
}

extension JSONEncoder {
    static let apiEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()
}

extension JSONDecoder {
    static let apiDecoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}

func randomBytes(count: Int) -> Data {
#if canImport(Security)
    var bytes = [UInt8](repeating: 0, count: count)
    let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(result == errSecSuccess, "Failed to generate secure random bytes")
    return Data(bytes)
#else
    Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
#endif
}

func jsonObject(from data: Data) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw HTTPError.badRequest("Expected JSON object")
    }
    return object
}

func parseWebAuthnClientData(_ data: Data) throws -> (type: String, challenge: String, origin: String?) {
    let object = try jsonObject(from: data)
    guard let type = object["type"] as? String else {
        throw HTTPError.badRequest("Missing client data type")
    }
    guard let challenge = object["challenge"] as? String else {
        throw HTTPError.badRequest("Missing client data challenge")
    }
    return (type, challenge, object["origin"] as? String)
}

func utcTimestampString(for date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
}

func normalizedOriginString(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count > 1 else {
        return trimmed
    }

    return trimmed.hasSuffix("/") ? String(trimmed.dropLast()) : trimmed
}
