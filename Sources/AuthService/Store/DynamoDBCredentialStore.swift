import AWSDynamoDB
import Foundation

actor DynamoDBCredentialStore: CredentialStoring {
    private let client: DynamoDBClient
    private let table: String
    init(configuration: ServiceConfiguration) async throws {
        let config = try await DynamoDBClient.DynamoDBClientConfig(region: configuration.awsRegion)
        self.client = DynamoDBClient(config: config)
        self.table = configuration.dynamoDBCredentialsTable
    }
    func credential(for username: String) async throws -> StoredCredential? {
        let result = try await client.getItem(input: GetItemInput(consistentRead: true, key: ["username": .s(username)], tableName: table))
        guard let item = result.item else { return nil }
        guard let idValue = item["credential_id"], case .b(let credentialID) = idValue,
              let userValue = item["user_id"], case .b(let userID) = userValue,
              let keyValue = item["public_key_x963"], case .b(let publicKey) = keyValue,
              let countValue = item["sign_count"], case .n(let count) = countValue, let signCount = UInt32(count) else {
            throw HTTPError.internalServerError("Malformed credential record")
        }
        return StoredCredential(credentialID: credentialID, username: username, userID: userID, publicKeyX963: publicKey, signCount: signCount)
    }
    func saveCredential(_ credential: StoredCredential) async throws {
        let item: [String: DynamoDBClientTypes.AttributeValue] = ["username": .s(credential.username),
            "credential_id": .b(credential.credentialID), "user_id": .b(credential.userID),
            "public_key_x963": .b(credential.publicKeyX963), "sign_count": .n(String(credential.signCount))]
        do {
            _ = try await client.putItem(input: PutItemInput(conditionExpression: "attribute_not_exists(username)", item: item, tableName: table))
        } catch is ConditionalCheckFailedException { throw HTTPError.conflict("Username already registered") }
    }
    func updateSignCount(username: String, signCount: UInt32) async throws {
        do {
            _ = try await client.updateItem(input: UpdateItemInput(conditionExpression: "attribute_exists(username) AND sign_count <= :count",
                expressionAttributeValues: [":count": .n(String(signCount))], key: ["username": .s(username)], tableName: table,
                updateExpression: "SET sign_count = :count"))
        } catch is ConditionalCheckFailedException { throw HTTPError.unauthorized("Authenticator sign count regressed") }
    }
}
