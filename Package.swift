// swift-tools-version: 5.7.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "jose-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .macCatalyst(.v15),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "jose-swift",
            targets: ["JWK"]
        ),
        .library(
            name: "Jose",
            targets: ["Jose"]
        ),
    ],
    dependencies: [
        // For `X448` support
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "3.1.4000")),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMinor(from: "0.13.0")),
        // For `AES_CBC_HMAC_SHA2`, `PBES2` and RSA DER encoding support
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.8.1"))
        // FOR `A256_CBC_HS512` with `ECDH-1PU-A256KW`
    ],
    targets: [
        .target(
            name: "Jose",
            dependencies: [
                "JWK",
                "JWS",
                "JWA",
                "JWE"
            ]
        ),
        .target(
            name: "JWA",
            dependencies: [
                "JWK",
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "CryptoSwift", package: "CryptoSwift")
            ]
        ),
        .testTarget(
            name: "JWATests",
            dependencies: ["JWA", "Tools"]
        ),
        .target(
            name: "JWS",
            dependencies: [
                "JWK",
                "JWA"
            ]
        ),
        .testTarget(
            name: "JWSTests",
            dependencies: ["JWS", "Tools"]
        ),
        .target(
            name: "JWE",
            dependencies: [
                "JWA",
                "JWK",
                "CryptoSwift"
            ]
        ),
        .testTarget(
            name: "JWETests",
            dependencies: ["JWE", "Tools"]
        ),
        .target(
            name: "JWK",
            dependencies: [
                "OpenSSL",
                "CryptoSwift",
                "Tools",
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]
        ),
        .testTarget(
            name: "JWKTests",
            dependencies: ["JWK", "Tools"]
        ),
        .target(
            name: "Tools"
        ),
    ]
)
