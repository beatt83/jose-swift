// swift-tools-version: 5.9.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "jose-swift",
    platforms: [
        .iOS(.v14),
        .macOS(.v12),
        .macCatalyst(.v14),
        .tvOS(.v14),
        .watchOS(.v6)
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
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0"),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMinor(from: "0.15.0")),
        // For `AES_CBC_HMAC_SHA2`, `PBES2` and RSA DER encoding support
        // Changing to a fork I made while I create a PR, since I found a bug
        .package(url: "https://github.com/beatt83/CryptoSwift.git", .upToNextMinor(from: "1.8.7")),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.7.0"),
        // FOR `A256_CBC_HS512` with `ECDH-1PU-A256KW`
        .package(url: "https://github.com/DLTAStudio/zlib.git",from:"1.0.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.3.1"))
    ],
    targets: [
        .target(
            name: "JSONWebAlgorithms",
            dependencies: [
                "JSONWebKey",
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Zlib", package: "ZLib"),
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
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
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
