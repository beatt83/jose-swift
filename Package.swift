// swift-tools-version: 5.9.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "jose-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
        .macCatalyst(.v15),
        .tvOS(.v15),
        .watchOS(.v7)
    ],
    products: [
        .library(
            name: "jose-swift",
            targets: [
                "JSONWebKey",
                "JSONWebAlgorithms",
                "JSONWebEncryption",
                "JSONWebSignature",
                "JSONWebToken"
            ]
        ),
        .library(
            name: "jose-swift-docs",
            targets: [
                "jose-swift",
            ]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", from: "0.23.0"),
        // For `AES_CBC_HMAC_SHA2`, `PBES2` and RSA DER encoding support
        // Changing to a fork I made while I create a PR, since I found a bug
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.19.0"),
        // FOR `A256_CBC_HS512` with `ECDH-1PU-A256KW`
        .package(url: "https://github.com/DLTAStudio/zlib.git", exact: "1.0.2"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.1")
    ],
    targets: [
        .target(
            name: "JSONWebAlgorithms",
            dependencies: [
                "JSONWebKey",
                .product(name: "libsecp256k1", package: "secp256k1.swift"),
                .product(name: "P256K", package: "secp256k1.swift"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Zlib", package: "zlib")
            ]
        ),
        .testTarget(
            name: "JWATests",
            dependencies: ["JSONWebAlgorithms", "Tools"]
        ),
        .target(
            name: "JSONWebSignature",
            dependencies: [
                "JSONWebKey",
                "JSONWebAlgorithms"
            ]
        ),
        .testTarget(
            name: "JWSTests",
            dependencies: ["JSONWebSignature", "Tools"]
        ),
        .target(
            name: "JSONWebEncryption",
            dependencies: [
                "JSONWebAlgorithms",
                "JSONWebKey",
                "CryptoSwift"
            ]
        ),
        .testTarget(
            name: "JWETests",
            dependencies: ["JSONWebEncryption", "Tools"]
        ),
        .target(
            name: "JSONWebKey",
            dependencies: [
                "CryptoSwift",
                "Tools",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        .testTarget(
            name: "JWKTests",
            dependencies: ["JSONWebKey", "JSONWebAlgorithms", "Tools"]
        ),
        .target(
            name: "JSONWebToken",
            dependencies: [
                "JSONWebKey",
                "JSONWebSignature",
                "JSONWebEncryption",
                .product(name: "X509", package: "swift-certificates"),
                "Tools"
            ]
        ),
        .testTarget(
            name: "JWTTests",
            dependencies: ["JSONWebToken", "Tools"]
        ),
        .testTarget(
            name: "ExampleTests",
            dependencies: ["JSONWebToken", "JSONWebKey", "JSONWebEncryption", "JSONWebSignature", "Tools"]
        ),
        .target(
            name: "Tools"
        ),
        // This target exists just to build documentation it should not be used for development
        .target(
            name: "jose-swift",
            dependencies: [
                "JSONWebKey",
                "JSONWebSignature",
                "JSONWebAlgorithms",
                "JSONWebEncryption",
                "JSONWebToken"
            ]
        ),
    ],
    swiftLanguageVersions: [.version("6"), .v5]
)
