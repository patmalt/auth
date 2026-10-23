import XCTest
import Foundation
import AWSDynamoDB
@testable import AuthService

@MainActor
final class GrantStoreTests: XCTestCase {
    static func exercise(_ store: any GrantStoring) async throws {
        let now = Date()
        let original = try GrantRecord(key: UUID().uuidString, value: "initial", expires: now.addingTimeInterval(300))
        let inserted = try await store.transact(expected: [], putting: [original], deleting: [], now: now)
        XCTAssertTrue(inserted)
        let candidates = try (0..<16).map { try GrantRecord(key: original.key, value: $0, expires: original.expires) }
        let wins = try await withThrowingTaskGroup(of: Bool.self) { group in
            for candidate in candidates {
                group.addTask { try await store.transact(expected: [original], putting: [candidate], deleting: [], now: now) }
            }
            var successes = 0
            for try await won in group { if won { successes += 1 } }
            return successes
        }
        XCTAssertEqual(wins, 1)
        let loaded = try await store.get(original.key, now: now)
        let current = try XCTUnwrap(loaded)
        let newKey = try GrantRecord(key: UUID().uuidString, value: "must not be written", expires: original.expires)
        let conflict = try await store.transact(expected: [original], putting: [newKey], deleting: [original.key], now: now)
        XCTAssertFalse(conflict)
        let absent = try await store.get(newKey.key, now: now)
        XCTAssertNil(absent)
        let unchanged = try await store.get(original.key, now: now)
        XCTAssertEqual(unchanged?.version, current.version)
        let expired = try await store.get(original.key, now: now.addingTimeInterval(301))
        XCTAssertNil(expired)
        let late = try await store.transact(expected: [current], putting: [], deleting: [current.key], now: now.addingTimeInterval(301))
        XCTAssertFalse(late)
    }
    func testMemoryTransactionContract() async throws { try await Self.exercise(InMemoryGrantStore()) }

}
