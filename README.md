# Jose Swift Library

[![Swift](https://img.shields.io/badge/swift-brightgreen.svg)]() [![iOS](https://img.shields.io/badge/ios-brightgreen.svg)]() [![MacOS](https://img.shields.io/badge/macos-brightgreen.svg)]() [![WatchOS](https://img.shields.io/badge/watchos-brightgreen.svg)]() [![TvOS](https://img.shields.io/badge/tvos-brightgreen.svg)]()

This library provides comprehensive support for the Jose suite of standards, including JWA (JSON Web Algorithms), JWK (JSON Web Key), JWE (JSON Web Encryption), JWS (JSON Web Signature), and JWT (JSON Web Token). These standards are integral to modern security protocols on the web, offering methods for secure key management, data encryption, signing, and representation of claims among different parties.


## References
- [JSON Web Signature (JWS) - RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- [JSON Web Encryption (JWE) - RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- [JSON Web Key (JWK) - RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- [JSON Web Algorithms (JWA) - RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- [JSON Web Token (JWT) - RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Available Algorithms

<table>
<tr><th>JWS Supported Algorithms </th><th>JWE Supported Algorithms</th><th>JWK Supported Key Types</th></tr>
<tr><td valign="top">

| Algorithm       | Supported |
|-----------------|-----------|
| HS256           |:white_check_mark:|
| HS384           |:white_check_mark:|
| HS512           |:white_check_mark:|
| RS256           |:white_check_mark:|
| RS384           |:white_check_mark:|
| RS512           |:white_check_mark:|
| ES256           |:white_check_mark:|
| ES384           |:white_check_mark:|
| ES512           |:white_check_mark:|
| PS256           |:white_check_mark:|
| PS384           |:white_check_mark:|
| PS512           |:white_check_mark:|
| EdDSA           |:white_check_mark:|

</td><td valign="top">

| Algorithm       | Supported |
|-----------------|-----------|
| RSA1_5          |:white_check_mark:|
| RSA-OAEP        |:white_check_mark:|
| RSA-OAEP-256    |:white_check_mark:|
| A128KW          |:white_check_mark:|
| A192KW          |:white_check_mark:|
| A256KW          |:white_check_mark:|
| DIRECT          |:white_check_mark:|
| ECDH-ES         |:white_check_mark:|
| ECDH-ES+A128KW  |:white_check_mark:|
| ECDH-ES+A192KW  |:white_check_mark:|
| ECDH-ES+A256KW  |:white_check_mark:|
| A128GCMKW       |:white_check_mark:|
| A192GCMKW       |:white_check_mark:|
| A256GCMKW       |:white_check_mark:|
| PBES2-HS256+A128KW |       |
| PBES2-HS384+A192KW |       |
| PBES2-HS512+A256KW |       |

</td><td valign="top">

| Key Type | Supported |
|----------|-----------|
| EC       |:white_check_mark:|
| RSA      |:white_check_mark:|
| OKT      |:white_check_mark:|
| OCK      |:white_check_mark:|

</td></tr> </table>

## Requirements

- Swift 5.7.1 or later
- iOS 15.0 or later
- macOS 12.0 or later
- Mac Catalyst 15.0 or later
- tvOS 15.0 or later
- watchOS 8.0 or later
- Dependencies:
    - [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)
    - [OpenSSL](https://github.com/krzyzanowskim/OpenSSL)
    - [secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift)

## Swift Package Manager (SPM)

To use the `jose-swift` package in your project, you need to add it as a dependency in your `Package.swift` file.

### Step 1: Add the Dependency

Open your `Package.swift` file and add the `jose-swift` package to your `dependencies` array. Make sure to specify the version you want to use:

```swift
dependencies: [
    .package(url: "https://github.com/your-username/jose-swift.git", .upToNextMinor(from: "1.0.0")),
    // ... other dependencies ...
]
```

### Step 2: Add the Target Dependency

In the same Package.swift file, add jose-swift to the dependencies of your target:

```swift
targets: [
    .target(
        name: "YourTargetName",
        dependencies: [
            "jose-swift",
            // ... other dependencies ...
        ]
    ),
    // ... other targets ...
]
```

### Step 3: Import and Use in Your Project

Once you've added the package as a dependency, you can import JWE, JWS, JWA, or JWK in your Swift files depending on what functionality you need:

```swift
import JWE
// or
import JWS
// or
import JWA
// or
import JWK
```

## Modules

### JWA (JSON Web Algorithms)
JWA specifies cryptographic algorithms used in the context of Jose to perform digital signing and content encryption. It includes standards for various types of algorithms like RSA, AES, HMAC, and more.

### JWK (JSON Web Key)
JWK is a standard way to represent cryptographic keys in a JSON format. This module provides functionalities for generating, parsing, and managing JWKs, which are essential for encryption, decryption, and signing processes.

### JWE (JSON Web Encryption)
JWE represents encrypted content using JSON-based data structures. This module includes comprehensive functionalities for encrypting and decrypting data, managing encryption keys, and handling various encryption algorithms and methods as specified in the standard.

### JWS (JSON Web Signature)
JWS is a standard for digitally signing arbitrary content. This module supports creating and verifying digital signatures, ensuring the integrity and authenticity of signed data.

### JWT (JSON Web Token) (WIP)
JWT is a compact, URL-safe means of representing claims to be transferred between two parties. This module offers tools for creating, parsing, validating, and manipulating JWTs, with support for various signing and encryption methods.

## Contributing
Contributions to the library are welcome. Please ensure that your contributions adhere to the Jose standards and add value to the existing functionalities.

## Acknowledgments

Special thanks to the [`swift-jose`](https://github.com/proxyco/swift-jose) repository by [Zsombor Szabo](https://github.com/zssz) for serving as an inspiration for this project. I have adopted parts of the `JWK` implementation and several test vectors from their work, which have been instrumental in shaping aspects of this library. Their contributions to the open-source community are sincerely appreciated.

## License
This project is licensed under the Apache License 2.0. See the LICENSE file for details.
