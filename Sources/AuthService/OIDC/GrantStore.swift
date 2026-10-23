import Foundation

struct GrantRecord: Codable, Sendable {
    let key: String
    let version: String
    let expires: Date
    let payload: Data

    init<T: Encodable>(key: String, value: T, expires: Date) throws {
        self.key = key
        self.version = UUID().uuidString
        self.expires = expires
        self.payload = try JSONEncoder().encode(value)
    }
    func decode<T: Decodable>(_ type: T.Type) throws -> T { try JSONDecoder().decode(type, from: payload) }
}

/// A transaction must check every expected revision AND its expiry, then apply all writes atomically.
/// New keys must not exist. Deletes require an expected revision. Conflicts return false; service errors throw.
protocol GrantStoring: Sendable {
    func get(_ key: String, now: Date) async throws -> GrantRecord?
    func transact(expected: [GrantRecord], putting: [GrantRecord], deleting: [String], now: Date) async throws -> Bool
}

actor InMemoryGrantStore: GrantStoring {
    private var records: [String: GrantRecord] = [:]
    func get(_ key: String, now: Date) -> GrantRecord? {
        guard let record = records[key], record.expires > now else { return nil }
        return record
    }
    func transact(expected: [GrantRecord], putting: [GrantRecord], deleting: [String], now: Date) -> Bool {
        records = records.filter { $0.value.expires > now }
        let revisions = Dictionary(uniqueKeysWithValues: expected.map { ($0.key, $0.version) })
        guard expected.allSatisfy({ records[$0.key]?.version == $0.version && $0.expires > now }),
              putting.allSatisfy({ revisions[$0.key] != nil || records[$0.key] == nil }),
              deleting.allSatisfy({ revisions[$0] != nil }) else { return false }
        for key in deleting { records.removeValue(forKey: key) }
        for record in putting { records[record.key] = record }
        return true
    }
}
