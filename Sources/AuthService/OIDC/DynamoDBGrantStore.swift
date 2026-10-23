import AWSDynamoDB
import Foundation

actor DynamoDBGrantStore: GrantStoring {
    private let client: DynamoDBClient
    private let table: String

    init(region: String, table: String, endpoint: String? = nil) async throws {
        let config = try await DynamoDBClient.DynamoDBClientConfig(region: region)
        if let endpoint { config.endpoint = endpoint }
        self.client = DynamoDBClient(config: config)
        self.table = table
    }

    func get(_ key: String, now: Date) async throws -> GrantRecord? {
        let result = try await client.getItem(input: GetItemInput(consistentRead: true, key: ["pk": .s(key)], tableName: table))
        guard let item = result.item else { return nil }
        guard let attribute = item["record"], case .b(let payload) = attribute else { throw HTTPError.internalServerError("Malformed grant record") }
        let record = try JSONDecoder().decode(GrantRecord.self, from: payload)
        guard record.key == key else { throw HTTPError.internalServerError("Grant key mismatch") }
        return record.expires > now ? record : nil
    }

    func transact(expected: [GrantRecord], putting: [GrantRecord], deleting: [String], now: Date) async throws -> Bool {
        let revisions = Dictionary(uniqueKeysWithValues: expected.map { ($0.key, $0.version) })
        let puts = Dictionary(uniqueKeysWithValues: putting.map { ($0.key, $0) })
        let deleted = Set(deleting)
        precondition(deleted.isDisjoint(with: puts.keys) && deleted.allSatisfy { revisions[$0] != nil })
        let keys = Set(expected.map(\.key)).union(puts.keys).union(deleted)
        var items: [DynamoDBClientTypes.TransactWriteItem] = []
        for key in keys.sorted() {
            let revision = revisions[key]
            let expression = revision == nil ? "attribute_not_exists(pk)" : "#v = :v AND expires_at > :now"
            let names: [String: String]? = revision == nil ? nil : ["#v": "version"]
            let values: [String: DynamoDBClientTypes.AttributeValue]? = revision.map {
                [":v": .s($0), ":now": .n(String(now.timeIntervalSince1970))]
            }
            if let record = puts[key] {
                let item: [String: DynamoDBClientTypes.AttributeValue] = ["pk": .s(key), "version": .s(record.version),
                    "expires_at": .n(String(record.expires.timeIntervalSince1970)),
                    "ttl": .n(String(Int(ceil(record.expires.timeIntervalSince1970)))),
                    "record": .b(try JSONEncoder().encode(record))]
                items.append(.init(put: .init(conditionExpression: expression, expressionAttributeNames: names,
                    expressionAttributeValues: values, item: item, tableName: table)))
            } else if deleted.contains(key) {
                items.append(.init(delete: .init(conditionExpression: expression, expressionAttributeNames: names,
                    expressionAttributeValues: values, key: ["pk": .s(key)], tableName: table)))
            } else {
                items.append(.init(conditionCheck: .init(conditionExpression: expression, expressionAttributeNames: names,
                    expressionAttributeValues: values, key: ["pk": .s(key)], tableName: table)))
            }
        }
        do {
            _ = try await client.transactWriteItems(input: TransactWriteItemsInput(transactItems: items))
            return true
        } catch let error as TransactionCanceledException {
            // Never hide IAM, capacity, schema, or transport failures as invalid credentials.
            if error.cancellationReasons?.contains(where: { $0.code == "ConditionalCheckFailed" || $0.code == "TransactionConflict" }) == true {
                return false
            }
            throw error
        }
    }
}
