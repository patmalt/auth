// swift-tools-version: 6.2

import PackageDescription

var products: [Product] = [
    .executable(name: "AuthService", targets: ["AuthService"]),
    .library(name: "AuthKit", targets: ["AuthKit"]),
]

var targets: [Target] = [
    .executableTarget(
        name: "AuthService",
        dependencies: [
            .product(name: "AWSDynamoDB", package: "aws-sdk-swift"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "Logging", package: "swift-log"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
        ]
    ),
    .target(
        name: "AuthKit",
    ),
    .testTarget(name: "AuthServiceTests", dependencies: ["AuthService"]),
]

#if os(macOS)
products.append(.executable(name: "AuthDemoMacApp", targets: ["AuthDemoMacApp"]))
targets.append(
    .executableTarget(
        name: "AuthDemoMacApp",
        dependencies: ["AuthKit"],
        path: "Samples/AuthDemoMacApp",
        exclude: ["AuthDemoMacApp.entitlements"]
    )
)
#endif

let package = Package(
    name: "auth",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: products,
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.3.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.4"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.66.0"),
        .package(url: "https://github.com/awslabs/aws-sdk-swift.git", from: "1.6.2"),
    ],
    targets: targets
)

