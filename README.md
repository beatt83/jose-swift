![Screenshot](jose-swift-logo.png)
# Jose Swift Library

[![Swift](https://img.shields.io/badge/swift-brightgreen.svg)]() [![Swift6](https://img.shields.io/badge/swift6-brightgreen.svg)]() [![iOS](https://img.shields.io/badge/ios-brightgreen.svg)]() [![MacOS](https://img.shields.io/badge/macos-brightgreen.svg)]() [![WatchOS](https://img.shields.io/badge/watchos-brightgreen.svg)]() [![TvOS](https://img.shields.io/badge/tvos-brightgreen.svg)]()

This library provides comprehensive support for the Jose suite of standards, including JWA (JSON Web Algorithms), JWK (JSON Web Key), JWE (JSON Web Encryption), JWS (JSON Web Signature), and JWT (JSON Web Token). These standards are integral to modern security protocols on the web, offering methods for secure key management, data encryption, signing, and representation of claims among different parties.

## Table of Contents
1. [Available Features and Algorithms](#available-features-and-algorithms)
2. [Requirements](#requirements)
3. [Swift Package Manager (SPM)](#swift-package-manager-spm)
   - [Step 1: Add the Dependency](#step-1-add-the-dependency)
   - [Step 2: Add the Target Dependency](#step-2-add-the-target-dependency)
   - [Step 3: Import and Use in Your Project](#step-3-import-and-use-in-your-project)
4. [Documentation](#documentation)
5. [Modules](#modules)
   - [JWK (JSON Web Key)](#jwk-json-web-key)
   - [JWS (JSON Web Signature)](#jws-json-web-signature)
   - [JWE (JSON Web Encryption)](#jwe-json-web-encryption)
   - [JWT (JSON Web Token)](#jwt-json-web-token)
   - [JWA (JSON Web Algorithms)](#jwa-json-web-algorithms)
6. [Contributing](#contributing)
7. [References](#references)
8. [Acknowledgments](#acknowledgments)
9. [License](#license)

## Available Features and Algorithms

### JWT

<table>
<tr><th>JWT supported algorithms</th><th>JWT supported types</th><th>JWT supported claims validations</th></tr>
</td><td valign="top">

| Algorithms         | Supported        |
|--------------------|------------------|
| All JWE algorithms |:white_check_mark:|
| All JWS algorithms |:white_check_mark:|

</td><td valign="top">

| Types            | Supported        |
|------------------|------------------|
| Signed           |:white_check_mark:|
| Encrypted        |:white_check_mark:|
| Nested Signed    |:white_check_mark:|
| Nested Encrypted |:white_check_mark:|

</td><td valign="top">

| Claims            | Supported        |
|-------------------|------------------|
| iss               |:white_check_mark:|
| sub               |:white_check_mark:|
| aud               |:white_check_mark:|
| nbf               |:white_check_mark:|
| exp               |:white_check_mark:|
| iat               |:white_check_mark:|
| typ               |:white_check_mark:|
| cty               |:white_check_mark:|
| DSL Claims Builder|:white_check_mark:|

</td></tr> </table>

### JWE

<table>
<tr><th>JWE Supported Types</th><th>JWE Supported Algorithms</th><th>JWE Supported Encodings</th></tr>
<tr><td valign="top">

| Type           | Supported        |
|----------------|------------------|
| Compact String |:white_check_mark:|
| JSON           |:white_check_mark:|
| JSON Flattened |:white_check_mark:|

</td><td valign="top">

| Algorithm          | Supported        |
|--------------------|------------------|
| RSA1_5             |:white_check_mark:|
| RSA-OAEP           |:white_check_mark:|
| RSA-OAEP-256       |:white_check_mark:|
| A128KW             |:white_check_mark:|
| A192KW             |:white_check_mark:|
| A256KW             |:white_check_mark:|
| DIRECT             |:white_check_mark:|
| ECDH-ES            |:white_check_mark:|
| ECDH-ES+A128KW     |:white_check_mark:|
| ECDH-ES+A192KW     |:white_check_mark:|
| ECDH-ES+A256KW     |:white_check_mark:|
| ECDH-1PU           |:white_check_mark:|
| ECDH-1PU+A128KW    |:white_check_mark:|
| ECDH-1PU+A192KW    |:white_check_mark:|
| ECDH-1PU+A256KW    |:white_check_mark:|
| A128GCMKW          |:white_check_mark:|
| A192GCMKW          |:white_check_mark:|
| A256GCMKW          |:white_check_mark:|
| PBES2-HS256+A128KW |:white_check_mark:|
| PBES2-HS384+A192KW |:white_check_mark:|
| PBES2-HS512+A256KW |:white_check_mark:|

</td><td valign="top">

| Encoding Algorithm | Supported     |
|-----------------|------------------|
| A128CBC-HS256   |:white_check_mark:|
| A128CBC-HS384   |:white_check_mark:|
| A128CBC-HS512   |:white_check_mark:|
| A128GCMKW       |:white_check_mark:|
| A192GCMKW       |:white_check_mark:|
| A256GCMKW       |:white_check_mark:|
| C20P            |:white_check_mark:|
| XC20P           |:white_check_mark:|

</td></tr> </table>

### JWS

<table>
<tr><th>JWS Supported Types</th><th>JWS Supported Algorithms</th></tr>
<tr><td valign="top">

| Type                | Supported        |
|---------------------|------------------|
| Compact String      |:white_check_mark:|
| JSON                |:white_check_mark:|
| JSON Flattened      |:white_check_mark:|
| Unencoded Payload\* |:white_check_mark:|

</td><td valign="top">

| Algorithm       | Supported        |
|-----------------|------------------|
| HS256           |:white_check_mark:|
| HS384           |:white_check_mark:|
| HS512           |:white_check_mark:|
| RS256           |:white_check_mark:|
| RS384           |:white_check_mark:|
| RS512           |:white_check_mark:|
| ES256           |:white_check_mark:|
| ES256K          |:white_check_mark:|
| ES384           |:white_check_mark:|
| ES512           |:white_check_mark:|
| PS256           |:white_check_mark:|
| PS384           |:white_check_mark:|
| PS512           |:white_check_mark:|
| EdDSA           |:white_check_mark:|

</td></tr> </table>

Note: JWS Unencoded payload as referenced in the [RFC-7797](https://datatracker.ietf.org/doc/html/rfc7797)

### JWK

<table>
<tr><th>JWK Supported Key Types</th></tr>
<tr><td valign="top">

| Key Type | Supported        |
|----------|------------------|
| EC       |:white_check_mark:|
| RSA      |:white_check_mark:|
| OKT      |:white_check_mark:|
| OCK      |:white_check_mark:|

</td></tr> </table>

## Requirements

- Swift 5.8.1 or later
- Swift 6 or later
- iOS 15.0 or later
- macOS 12.0 or later
- Mac Catalyst 15.0 or later
- tvOS 15.0 or later
- watchOS 8.0 or later
- Dependencies:
    - [CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)
    - [secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift)

## Swift Package Manager (SPM)

To use the `jose-swift` package in your project, you need to add it as a dependency in your `Package.swift` file.

### Step 1: Add the Dependency

Open your `Package.swift` file and add the `jose-swift` package to your `dependencies` array. Make sure to specify the version you want to use:

```swift
dependencies: [
    .package(url: "https://github.com/beatt83/jose-swift.git", .upToNextMinor(from: "2.4.0")),
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

Once you've added the package as a dependency, you can import JSONWebEncryption, JWS, JWA, or JWK in your Swift files depending on what functionality you need:

```swift
import JSONWebEncryption
// or
import JSONWebSignature
// or
import JSONWebAlgorithms
// or
import JSONWebKey
// or
import JSONWebToken
```

## Documentation

You can access [here](https://beatt83.github.io/jose-swift/documentation/jose_swift/) to the documentation.

### Getting Started

For a quick guide on how to use the library please visit the [Getting Started](https://beatt83.github.io/jose-swift/documentation/jose-swift/gettingstarted) tutorial.

For more examples on how to use this library please try to check the unit tests, they are extensive and should provide more information.

## Modules

### JWK (JSON Web Key)
JWK is a standard way to represent cryptographic keys in a JSON format, as defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517). This module provides functionalities for generating, parsing, and managing JWKs, which are essential for encryption, decryption, and signing processes.

Please check our documentation for more on [JWS Signatures](https://beatt83.github.io/jose-swift/documentation/jose-swift/jwssignatures).

```swift
let keyJWK = JWK(keyType: .rsa, algorithm: "A256GCM", keyID: rsaKeyId, e: rsaKeyExponent, n: rsaKeyModulus)
// ---------------------
let key = secp256k1.Signing.PrivateKey()
let keyJWK = key.jwkRepresentation
// ---------------------
let key = Curve25519.KeyAgreement.PrivateKey()
let publicKeyJWK = key.jwkRepresentation.publicKey
```

### JWS (JSON Web Signature)
JWS is a standard for digitally signing arbitrary content, as detailed in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515). This module supports creating and verifying digital signatures, ensuring the integrity and authenticity of signed data.

#### Supported Algorithms:
- RS256 (RSA Signature with SHA-256)
- RS384 (RSA Signature with SHA-384)
- RS512 (RSA Signature with SHA-512)
- HS256 (HMAC with SHA-256)
- HS384 (HMAC with SHA-384)
- HS512 (HMAC with SHA-512)
- ES256 (ECDSA using P-256 and SHA-256)
- ES384 (ECDSA using P-384 and SHA-384)
- ES512 (ECDSA using P-521 and SHA-512)
- ES256K (ECDSA using secp256k1 and SHA-256)
- PS256 (RSA PSS with SHA-256)
- PS384 (RSA PSS with SHA-384)
- PS512 (RSA PSS with SHA-512)
- EdDSA (EdDSA using Ed25519) - [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)

### Bouncy castle secp256k1 failsafe

There is a difference between the signatures given by Bouncy castle a prominent cryptographic Java library and used with Nimbus JWT and bitcoin secp256k1. The signatures are in DER format and for some reason the R and S are reverted.

To have signatures that are verifiable by Bouncy Castle you can set this flag `ES256KSigner.outputFormat = .der`, it will transform the signatures in DER format.

With this in mind this library provides a functionality to enable verification of Nimbus/Bouncy Castle signatures, this can be enabled by setting the flag `ES256KVerifier.bouncyCastleFailSafe = true`. This process requires manipualtion of the internal signature, and reverses the R and S bytes, use it at your own risk since it can add security flaw.

Example:

```swift
let payload = "Hello world".data(using: .utf8)!
let key = secp256k1.Signing.PrivateKey()

let jws = try JWS(payload: payload, key: key)

let jwsString = jws.compactSerialization

try JWS(jwsString: jwsString).verify(key: key)
```

If you want to add additional headers beyond the default to the JWS:

```swift
let rsaKeyId = "Hello-keyId"
var header = DefaultJWSHeaderImpl()
header.keyID = rsaKeyId
header.algorithm = .rsa512

let keyJWK = JWK(keyType: .rsa, algorithm: "RSA512", keyID: rsaKeyId, e: rsaKeyExponent, n: rsaKeyModulus)
let jwe = try JWS(payload: payload, protectedHeader: header, key: jwk)
```

### JWS with Unencoded payload (Compact string only)

JWS also supports unencoded payloads, which is useful in scenarios where the payload is already in a compact, URL-safe form (such as in the case of small JSON objects or base64url-encoded strings). This can help reduce the overall size of the JWS and improve performance by avoiding redundant encoding steps.

To create a JWS with an unencoded payload, you need to set the b64 header parameter to false and ensure the payload is in a compatible format.

Example:

```
let payload = "Hello world".data(using: .utf8)!
let key = secp256k1.Signing.PrivateKey()

let jws = try JWS(payload: payload, key: key, options: [.unencodedPayload])

let jwsString = jws.compactSerialization

try JWS.verify(jwsString: jwsString, payload: payload, key: key)
```


### JWE (JSON Web Encryption)
JWE represents encrypted content using JSON-based data structures, following the guidelines of [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516). This module includes functionalities for encrypting and decrypting data, managing encryption keys, and handling various encryption algorithms and methods.

Please check our documentation for more on [JWE Encryption](https://beatt83.github.io/jose-swift/documentation/jose-swift/jweencryption).

#### Supported Algorithms:

1. **Key Management Algorithms**:
    - RSA1_5 (RSAES-PKCS1-v1_5)
    - RSA-OAEP (RSAES OAEP using default parameters)
    - RSA-OAEP-256 (RSAES OAEP using SHA-256 and MGF1 with SHA-256)
    - A128KW (AES Key Wrap with default 128-bit key)
    - A192KW (AES Key Wrap with 192-bit key)
    - A256KW (AES Key Wrap with 256-bit key)
    - dir (Direct use of a shared symmetric key)
    - ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static key agreement)
    - ECDH-ES+A128KW (ECDH-ES using Concat KDF and A128KW wrapping)
    - ECDH-ES+A192KW (ECDH-ES using Concat KDF and A192KW wrapping)
    - ECDH-ES+A256KW (ECDH-ES using Concat KDF and A256KW wrapping)
    - ECDH-1PU (Elliptic Curve Diffie-Hellman One-Pass Unified Model)
    - ECDH-1PU+A128KW (ECDH-1PU using Concat KDF and A128KW wrapping)
    - ECDH-1PU+A192KW (ECDH-1PU using Concat KDF and A192KW wrapping)
    - ECDH-1PU+A256KW (ECDH-1PU using Concat KDF and A256KW wrapping)
    - A128GCMKW (Key wrapping with AES GCM using 128-bit key)
    - A192GCMKW (Key wrapping with AES GCM using 192-bit key)
    - A256GCMKW (Key wrapping with AES GCM using 256-bit key)
    - PBES2-HS256+A128KW (PBES2 with HMAC SHA-256 and "A128KW" wrapping)
    - PBES2-HS384+A192KW (PBES2 with HMAC SHA-384 and "A192KW" wrapping)
    - PBES2-HS512+A256KW (PBES2 with HMAC SHA-512 and "A256KW" wrapping)
    - Note: ECDH-1PU is specified in [draft-ietf-jose-cfrg-curves-10](https://datatracker.ietf.org/doc/draft-ietf-jose-cfrg-curves/10/)

2. **Content Encryption Algorithms**:
    - A128CBC-HS256 (AES CBC using 128-bit key with HMAC SHA-256)
    - A192CBC-HS384 (AES CBC using 192-bit key with HMAC SHA-384)
    - A256CBC-HS512 (AES CBC using 256-bit key with HMAC SHA-512)
    - A128GCM (AES GCM using 128-bit key)
    - A192GCM (AES GCM using 192-bit key)
    - A256GCM (AES GCM using 256-bit key)
    - C20P (ChaCha20-Poly1305)
    - XC20P (XChaCha20-Poly1305)
    - Note: ChaChaPoly20-Poly1305 and XChaChaPoly20-Poly1305 is specified in [draft-amringer-jose-chacha-02](https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha-02)
    
3. **Compression Algorithms**:
    - DEFLATE (zip)

Example1:

```swift
let payload = "Hello world".data(using: .utf8)!
let keyJWK = JWK(keyType: .rsa, algorithm: "A256GCM", keyID: rsaKeyId, e: rsaKeyExponent, n: rsaKeyModulus)


let serialization = try JWE(
    payload: payload,
    keyManagementAlg: .a256KW,
    encryptionAlgorithm: .a256GCM,
    compressionAlgorithm: .deflate,
    recipientKey: keyJWK
)

let compact = serialization.compactSerialization

let jwe = try JWE(compactString: compact)
let decrypted = try jwe.decrypt(recipientKey: recipientKey)
```

Example2:

```swift
let payload = "Hello world".data(using: .utf8)!
let key = P256.Signing.PrivateKey()


let serialization = try JWE(
    payload: payload,
    keyManagementAlg: .a256KW,
    encryptionAlgorithm: .a256GCM,
    compressionAlgorithm: .deflate,
    recipientKey: key
)

let compact = serialization.compactSerialization()

let jwe = try JWE(compactString: compact)
let decrypted = try jwe.decrypt(recipientKey: recipientJWK)
```

If you want to add additional headers beyond the default to the JWE:

```swift
let rsaKeyId = "Hello-keyId"
var header = DefaultJWEHeaderImpl()
header.keyID = rsaKeyId
header.keyManagementAlgorithm = .rsaOAEP256
header.encodingAlgorithm = .a256GCM
let keyJWK = JWK(keyType: .rsa, algorithm: "A256GCM", keyID: rsaKeyId, e: rsaKeyExponent, n: rsaKeyModulus)
let jwe = try JWE(payload: wrappedPayload, protectedHeader: header, recipientKey: jwk)
```


### JWT (JSON Web Token)
JWT is a compact, URL-safe means of representing claims to be transferred between two parties. This module offers tools for creating, parsing, validating, and manipulating JWTs, with support for various signing and encryption methods, as specified in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

Please check our documentation for more on [JWT tokens](https://beatt83.github.io/jose-swift/documentation/jose-swift/jwtconcepts).

#### Features:

1. **Signed JWTs**:
    - Supports digital signatures to verify the authenticity and integrity of the token.
    - Utilizes JWS (JSON Web Signature) standards.
    - Supports all JWS algorithms previously mentioned.

2. **Encrypted JWTs**:
    - Facilitates encryption of token content for confidentiality.
    - Uses JWE (JSON Web Encryption) for robust encryption standards.
    - Supports all JWE algorithms previously mentioned.

3. **Nested JWT (JWS + JWE)**:
    - Implements Nested JWTs where a JWT is signed and then encrypted, providing both the benefits of JWS and JWE.
    - Ensures that a token is first authenticated (JWS) and then secured for privacy (JWE).
    
4. **Domain-specific language (DSL) for Claim Creation**:
    - Allows for a more declarative approach to creating claims using a domain-specific language (DSL).
    - Facilitates the creation of both standard and custom claims in a readable and structured manner.

5. **Claim Validation**:
    - Offers extensive capabilities to validate JWT claims.
    - Includes standard claims like issuer (`iss`), subject (`sub`), audience (`aud`), expiration (`exp`), not before (`nbf`), and issued at (`iat`).
    - Custom claim validation to meet specific security requirements.

Example:

- Signed JWT

```swift
let key = P256.Signing.PrivateKey()
let mockClaims = DefaultJWTClaims(
    iss: "testAlice",
    sub: "Alice",
    exp: expiredAt
)

let jwt = try JWT.signed(
    payload: mockClaims,
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: key
)

let jwtString = jwt.jwtString

let verifiedJWT = try JWT<DefaultJWTClaims>.verify(jwtString: jwtString, senderKey: key)
let verifiedPayload = verifiedJWT.payload
```

- Encrypted JWT

```swift
let key = Curve25519.KeyAgreement.PrivateKey()
let mockClaims = DefaultJWTClaims(
    iss: "testAlice",
    sub: "Alice",
    exp: expiredAt
)

let jwt = try JWT.encrypt(
    payload: payload,
    protectedHeader: DefaultJWSHeaderImpl(keyManagementAlgorithm: .a128KW, encodingAlgorithm: .a128CBCHS256),
    recipientKey: key
)

let jwtString = jwt.jwtString

let verifiedJWT = try JWT<DefaultJWTClaims>.verify(jwtString: jwtString, recipientKey: key)
let verifiedPayload = verifiedJWT.payload
```

- DSL for Creating Claims
    - Standard Claims on signing a JWT
    
    ```swift
    let key = P256.Signing.PrivateKey()

    let jwt = try JWT.signed(
        payload: {
            IssuerClaim(value: "testIssuer")
            SubjectClaim(value: "testSubject")
            ExpirationTimeClaim(value: Date())
            IssuedAtClaim(value: Date())
            NotBeforeClaim(value: Date())
            JWTIdentifierClaim(value: "ThisIdentifier")
            AudienceClaim(value: "testAud")
        },
        protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
        key: key
    ).jwtString
    ```
    
    - Custom Claims
    
    ```swift
    let jsonClaimsObject = JWTClaimsBuilder.build {
        StringClaim(key: "testStr1", value: "value1")
        NumberClaim(key: "testN1", value: 0)
        NumberClaim(key: "testN2", value: 1.1)
        NumberClaim(key: "testN3", value: Double(1.233232))
        BoolClaim(key: "testBool1", value: true)
        ArrayClaim(key: "testArray") {
            ArrayElementClaim.string("valueArray1")
            ArrayElementClaim.string("valueArray2")
            ArrayElementClaim.bool(true)
            ArrayElementClaim.array {
                ArrayElementClaim.string("nestedNestedArray1")
            }
            ArrayElementClaim.object {
                StringClaim(key: "nestedNestedObject", value: "nestedNestedValue")
            }
        }
        ObjectClaim(key: "testObject") {
            StringClaim(key: "testDicStr1", value: "valueDic1")
        }
    }
    
    // Output
    // {
    //    "testBool1":true,
    //    "testArray":[
    //         "valueArray1",
    //          "valueArray2",
    //          true,
    //          ["nestedNestedArray1"],
    //          {
    //              "nestedNestedObject":"nestedNestedValue"
    //          }
    //      ],
    //      "testObject":{
    //          "testDicStr1":"valueDic1"
    //      },
    //      "testN1":0,
    //      "testStr1":"value1",
    //      "testN3":1.233232,
    //      "testN2":1.1
    // }
    ```

### JWA (JSON Web Algorithms)
JWA specifies cryptographic algorithms used in the context of Jose to perform digital signing and content encryption, as detailed in [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518). It includes standards for various types of algorithms like RSA, AES, HMAC, and more.


## Contributing
Contributions to the library are welcome. Please ensure that your contributions adhere to the Jose standards and add value to the existing functionalities.

## References
- [JSON Web Signature (JWS) - RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
- [JSON Web Encryption (JWE) - RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
- [JSON Web Key (JWK) - RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
- [JSON Web Algorithms (JWA) - RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
- [JSON Web Token (JWT) - RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Acknowledgments

Special thanks to the [`swift-jose`](https://github.com/proxyco/swift-jose) repository by [Zsombor Szabo](https://github.com/zssz) for serving as an inspiration for this project. I have adopted parts of the `JWK` implementation and several test vectors from their work, which have been instrumental in shaping aspects of this library. Their contributions to the open-source community are sincerely appreciated.

## License
This project is licensed under the Apache License 2.0. See the LICENSE file for details.
