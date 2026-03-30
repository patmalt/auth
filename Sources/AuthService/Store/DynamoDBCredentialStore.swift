import AWSDynamoDB
import Foundation

actor DynamoDBCredentialStore: CredentialStoring {
    private let client: DynamoDBClient
    private let credentialsTable: String
    private let challengesTable: String

    init(configuration: ServiceConfiguration) async throws {
        let config = try await DynamoDBClient.DynamoDBClientConfig(region: configuration.awsRegion)
        self.client = DynamoDBClient(config: config)
        self.credentialsTable = configuration.dynamoDBCredentialsTable
        self.challengesTable = configuration.dynamoDBChallengesTable
    }

    func saveChallenge(_ challenge: ChallengeRecord) async throws {
        let item: [String: DynamoDBClientTypes.AttributeValue] = [
            "username": .s(challenge.username),
            "challenge": .b(challenge.challenge),
            "user_id": .b(challenge.userID),
            "kind": .s(challenge.kind.rawValue),
            "expires_at": .n(String(Int(challenge.expiresAt.timeIntervalSince1970))),
        ]
        do {
            _ = try await client.putItem(input: PutItemInput(item: item, tableName: challengesTable))
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "PutItem",
                tableName: challengesTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
    }

    func takeChallenge(username: String, kind: ChallengeKind) async throws -> ChallengeRecord {
        let key: [String: DynamoDBClientTypes.AttributeValue] = ["username": .s(username)]
        let output: GetItemOutput
        do {
            output = try await client.getItem(input: GetItemInput(key: key, tableName: challengesTable))
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "GetItem",
                tableName: challengesTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
        guard let item = output.item else {
            throw HTTPError.badRequest("No active challenge for \(username)")
        }

        let record = try challengeRecord(from: item)
        guard record.kind == kind else {
            throw HTTPError.badRequest("Challenge kind mismatch")
        }
        guard record.expiresAt > Date() else {
            try await deleteChallenge(withKey: key)
            throw HTTPError.badRequest("Challenge expired")
        }

        try await deleteChallenge(withKey: key)
        return record
    }

    func credential(for username: String) async throws -> StoredCredential? {
        let key: [String: DynamoDBClientTypes.AttributeValue] = ["username": .s(username)]
        let output: GetItemOutput
        do {
            output = try await client.getItem(input: GetItemInput(key: key, tableName: credentialsTable))
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "GetItem",
                tableName: credentialsTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
        guard let item = output.item else {
            return nil
        }
        return try storedCredential(from: item)
    }

    func saveCredential(_ credential: StoredCredential) async throws {
        let item: [String: DynamoDBClientTypes.AttributeValue] = [
            "username": .s(credential.username),
            "credential_id": .b(credential.credentialID),
            "user_id": .b(credential.userID),
            "public_key_x963": .b(credential.publicKeyX963),
            "sign_count": .n(String(credential.signCount)),
        ]
        do {
            _ = try await client.putItem(input: PutItemInput(item: item, tableName: credentialsTable))
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "PutItem",
                tableName: credentialsTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
    }

    func updateSignCount(username: String, signCount: UInt32) async throws {
        let input = UpdateItemInput(
            expressionAttributeValues: [
                ":sign_count": .n(String(signCount)),
            ],
            key: ["username": .s(username)],
            tableName: credentialsTable,
            updateExpression: "SET sign_count = :sign_count"
        )
        do {
            _ = try await client.updateItem(input: input)
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "UpdateItem",
                tableName: credentialsTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
    }

    private func deleteChallenge(withKey key: [String: DynamoDBClientTypes.AttributeValue]) async throws {
        do {
            _ = try await client.deleteItem(input: DeleteItemInput(key: key, tableName: challengesTable))
        } catch {
            throw mapDynamoDBError(
                error,
                operation: "DeleteItem",
                tableName: challengesTable,
                expectedSchema: "partition key `username` (String)"
            )
        }
    }

    private func storedCredential(from item: [String: DynamoDBClientTypes.AttributeValue]) throws -> StoredCredential {
        guard let username = item["username"]?.stringValue,
              let credentialID = item["credential_id"]?.dataValue,
              let userID = item["user_id"]?.dataValue,
              let publicKey = item["public_key_x963"]?.dataValue,
              let signCountString = item["sign_count"]?.numberValue,
              let signCount = UInt32(signCountString) else {
            throw HTTPError.internalServerError("Credential record in DynamoDB is malformed")
        }
        return StoredCredential(
            credentialID: credentialID,
            username: username,
            userID: userID,
            publicKeyX963: publicKey,
            signCount: signCount
        )
    }

    private func challengeRecord(from item: [String: DynamoDBClientTypes.AttributeValue]) throws -> ChallengeRecord {
        guard let username = item["username"]?.stringValue,
              let challenge = item["challenge"]?.dataValue,
              let userID = item["user_id"]?.dataValue,
              let kindString = item["kind"]?.stringValue,
              let kind = ChallengeKind(rawValue: kindString),
              let expiresString = item["expires_at"]?.numberValue,
              let expires = Double(expiresString) else {
            throw HTTPError.internalServerError("Challenge record in DynamoDB is malformed")
        }
        return ChallengeRecord(
            challenge: challenge,
            username: username,
            userID: userID,
            kind: kind,
            expiresAt: Date(timeIntervalSince1970: expires)
        )
    }

    private func mapDynamoDBError(
        _ error: Error,
        operation: String,
        tableName: String,
        expectedSchema: String
    ) -> Error {
        let description = String(describing: error)
        if description.contains("ValidationException") {
            return HTTPError.internalServerError(
                "DynamoDB \(operation) failed validation for table \(tableName). " +
                "This service expects \(expectedSchema). " +
                "A common cause is that the live table uses a different key name, has a sort key, or stores `username` with a non-String type. " +
                "Original AWS error: \(description)"
            )
        }

        return HTTPError.internalServerError("DynamoDB \(operation) failed for table \(tableName): \(description)")
    }
}

private extension DynamoDBClientTypes.AttributeValue {
    var stringValue: String? {
        guard case .s(let value) = self else { return nil }
        return value
    }

    var dataValue: Data? {
        guard case .b(let value) = self else { return nil }
        return value
    }

    var numberValue: String? {
        guard case .n(let value) = self else { return nil }
        return value
    }
}
