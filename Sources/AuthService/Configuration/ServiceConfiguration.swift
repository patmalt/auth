import Foundation
import Logging

struct ServiceConfiguration {
    let host: String
    let port: Int
    let relyingPartyID: String
    let relyingPartyName: String
    let origin: String
    let corsAllowedOrigins: Set<String>
    let storeDriver: String
    let awsRegion: String
    let dynamoDBCredentialsTable: String
    let dynamoDBChallengesTable: String
    let jwtIssuer: String
    let jwtAudience: String
    let jwtSecret: String
    let tokenLifetime: TimeInterval
    let logLevel: Logger.Level

    static func fromEnvironment() -> ServiceConfiguration {
        let environment = ProcessInfo.processInfo.environment
        let configuredOrigin = normalizedOriginString(environment["RP_ORIGIN"] ?? "https://example.com")
        let configuredCORSOrigins = parseConfiguredOrigins(
            environment["CORS_ALLOWED_ORIGINS"],
            fallback: configuredOrigin
        )
        return ServiceConfiguration(
            host: environment["AUTH_HOST"] ?? "0.0.0.0",
            port: Int(environment["AUTH_PORT"] ?? "8080") ?? 8080,
            relyingPartyID: environment["RP_ID"] ?? "example.com",
            relyingPartyName: environment["RP_NAME"] ?? "Auth Demo",
            origin: configuredOrigin,
            corsAllowedOrigins: configuredCORSOrigins,
            storeDriver: environment["STORE_DRIVER"] ?? "memory",
            awsRegion: environment["AWS_REGION"] ?? "us-east-1",
            dynamoDBCredentialsTable: environment["DYNAMODB_CREDENTIALS_TABLE"] ?? "PasskeyCredentials",
            dynamoDBChallengesTable: environment["DYNAMODB_CHALLENGES_TABLE"] ?? "PasskeyChallenges",
            jwtIssuer: environment["JWT_ISSUER"] ?? "auth-service",
            jwtAudience: environment["JWT_AUDIENCE"] ?? "auth-clients",
            jwtSecret: environment["JWT_SECRET"] ?? "replace-me-in-secrets-manager",
            tokenLifetime: TimeInterval(environment["JWT_LIFETIME_SECONDS"] ?? "3600") ?? 3600,
            logLevel: Logger.Level(environmentVariable: environment["AUTH_LOG_LEVEL"])
        )
    }
}

private func parseConfiguredOrigins(_ value: String?, fallback: String) -> Set<String> {
    let origins = value?
        .split(separator: ",")
        .map { normalizedOriginString(String($0)) }
        .filter { !$0.isEmpty } ?? []

    return origins.isEmpty ? [fallback] : Set(origins)
}
