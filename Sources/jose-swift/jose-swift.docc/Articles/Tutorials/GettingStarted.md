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
    payload: {
        // Define the claims
        SubClaim(value: "1234567890")
        IatClaim(value: Date())
        StringClaim(key: "name", value: "John Doe")
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: privateKey
)
```

## Verifying a JWT

To verify a JWT, you need the corresponding public key. Extract the public key from the private key and use it to verify the JWT:

```swift
// Extract the public key
let publicKey = privateKey.publicKey

// Verify the JWT
let isValid = try jwt.verify(key: publicKey)
```

## Creating a JSON Web Signature (JWS)

A JSON Web Signature (JWS) is used to provide integrity and authenticity to data. Let's create and sign a JWS.

```swift
import JSONWebKey
import JSONWebSignature

// Define the payload
let payload = "Hello, JWS!".data(using: .utf8)!

// Create and sign the JWS
let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: privateKey)
```

## Verifying a JWS

To verify a JWS, you need the corresponding public key:

```swift
// Verify the JWS
let isJWSValid = try jws.verify(key: publicKey)
```

## Creating a JSON Web Encryption (JWE)

A JSON Web Encryption (JWE) is used to provide confidentiality to data. Let's create and encrypt a JWE.

```swift
import JSONWebKey
import JSONWebEncryption

// Define the payload
let payload = "Hello, JWE!".data(using: .utf8)!

// Create and encrypt the JWE
let recipientKey = P256.KeyAgreement.PublicKey()
let jwe = try JWE(payload: payload, keyManagementAlg: .ECDH_ES_A256KW, encryptionAlgorithm: .A256GCM, recipientKey: recipientKey)
```

## Decrypting a JWE

To decrypt a JWE, you need the corresponding private key:

```swift
// Decrypt the JWE
let decryptedPayload = try jwe.decrypt(recipientKey: privateKey)
```

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
let isJWSValid = try jws.verify(key: secPublicKey)
```

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

That's it! You are now ready to use the **jose-swift** library to handle JWT, JWS, and JWE in your Swift applications.
