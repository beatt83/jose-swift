# Getting Started with jose-swift

Welcome to the **jose-swift** library! This guide will help you get started with using JSON Web Tokens (JWT), JSON Web Signatures (JWS), and JSON Web Encryption (JWE) in your Swift applications.

## Installation

To install the **jose-swift** library, you can use Swift Package Manager. Add the following dependency to your `Package.swift` file:

```
dependencies: [
    .package(url: "https://github.com/beatt83/jose-swift.git", from: "2.4.0")
]
```

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

## Creating a JSON Web Token (JWT)

A JSON Web Token (JWT) is a compact, URL-safe token used for securely transmitting information between parties. Let's start by creating a JWT.

### Creating and Signing a JWT

To create and sign a JWT, you need a private key. Here, we'll use a `P256` private key for signing:

```swift
import JSONWebKey
import JSONWebToken

// Generate a P256 private key
let privateKey = P256.Signing.PrivateKey()

// Create and sign the JWT
let jwt = try JWT.signed(
    claims: {
        // Define the claims
        SubjectClaim(value: "1234567890")
        IssuedAtClaim(value: Date())
        StringClaim(key: "name", value: "John Doe")
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: privateKey
)

print(jwt.jwtString)
```
Example 1.1

## Verifying a JWT

To verify a JWT, you need the corresponding public key. Extract the public key from the private key and use it to verify the JWT:

```swift
// Extract the public key
let publicKey = privateKey.publicKey

// Verify the JWT
let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: publicKey)
```
Example 1.2

## Creating a JSON Web Signature (JWS)

A JSON Web Signature (JWS) is used to provide integrity and authenticity to data. Let's create and sign a JWS.

```swift
import JSONWebKey
import JSONWebSignature
import CryptoKit

// Generate a P256 private key
let privateKey = P256.Signing.PrivateKey()

// Define the payload
let payload = "Hello, JWS!".data(using: .utf8)!

// Create and sign the JWS
let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: privateKey)

print(jws.compactSerialization)
```
Example 1.3

## Verifying a JWS

To verify a JWS, you need the corresponding public key:

```swift
// Extract the public key
let publicKey = privateKey.publicKey

// Verify the JWS
let isJWSValid = try jws.verify(key: publicKey)
```
Example 1.4

## Creating a JSON Web Encryption (JWE)

A JSON Web Encryption (JWE) is used to provide confidentiality to data. Let's create and encrypt a JWE.

```swift
import JSONWebKey
import JSONWebEncryption

// Define the payload
let payload = "Hello, JWE!".data(using: .utf8)!

// Define the payload
let payload = "Hello, JWE!".data(using: .utf8)!

// Create and encrypt the JWE, only for example purpose on a production environment, on ECDHES the encryptor encrypts the content for the recipient PUBLIC KEY, only the recipient with his private key pair can decrypt it.
let recipientKey = P256.KeyAgreement.PrivateKey()

let jwe = try JWE(payload: payload, keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM, recipientKey: recipientKey.publicKey)

print(jwe.compactSerialization)
```
Example 1.5

## Decrypting a JWE

To decrypt a JWE, you need the corresponding private key:

```swift
// Decrypt the JWE
let decryptedPayload = try jwe.decrypt(recipientKey: recipientKey)

print("Encrypted payload: \(String(data: decryptedPayload, encoding: .utf8))")
```
Example 1.6

## Using SecKey for Signing and Verification

You can also use `SecKey` for signing and verifying JWS and JWT.

```swift
// Generate a SecKey private key
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256
]
var error: Unmanaged<CFError>?
guard let secPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    fatalError("Failed to generate private key: \(error!.takeRetainedValue())")
}

// Sign a JWS using SecKey
let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: secPrivateKey)

//Verify the JWS using SecKey
let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!
let isJWSValid = try jws.verify(key: publicKey)
```
Example 1.7

## Using JWK for Signing and Verification

You can also use a JWK (JSON Web Key) for signing and verifying JWS and JWT.

```swift
// Create a JWK
let jwk = JWK(octetSequence: Data(repeating: 0, count: 32))

// Sign a JWS using JWK
let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256), key: jwk)

// Verify the JWS using JWK
let isJWSValid = try jws.verify(key: jwk)
```
Example 1.8

That's it! You are now ready to use the **jose-swift** library to handle JWT, JWS, and JWE in your Swift applications.
