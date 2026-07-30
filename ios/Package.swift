// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EvanProxy",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "EvanProxy", targets: ["EvanProxy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-generator", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-openapi-runtime", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-openapi-urlsession", from: "1.0.2"),
        .package(url: "https://github.com/apple/swift-http-types", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "EvanProxy",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
                .product(name: "OpenAPIURLSession", package: "swift-openapi-urlsession"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
            ],
            resources: [.process("Resources")],
            plugins: [
                .plugin(name: "OpenAPIGenerator", package: "swift-openapi-generator"),
            ]
        ),
        // Tests are compiled by the EvanProxyAppTests target in App/ so they run
        // hosted in an app — the iOS simulator keychain rejects unhosted test
        // bundles with errSecMissingEntitlement (-34018).
    ]
)
