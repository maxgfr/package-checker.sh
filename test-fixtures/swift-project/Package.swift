// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "swift-project",
    products: [
        .executable(name: "swift-project", targets: ["swift-project"])
    ],
    dependencies: [
        // Mixed-case host/path on purpose: proves URL canonicalization
        // (scheme-strip + .git-strip + lowercase) matches feed emission,
        // which always lowercases (see canon_purl_name's swift branch).
        .package(url: "https://GitHub.com/Apple/Swift-NIO.git", exact: "2.10.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-atomics.git", branch: "main"),
    ],
    targets: [
        .executableTarget(
            name: "swift-project",
            dependencies: [
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Atomics", package: "swift-atomics"),
            ]
        )
    ]
)
