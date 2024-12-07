# Verifying JSON Web Tokens (JWTs)

This guide will walk you through verifying JSON Web Tokens (JWTs) using the **jose-swift** library. JWT verification ensures that the token has not been tampered with and that it was signed by a trusted source.

## Prerequisites

Ensure you have the **jose-swift** library installed and imported in your project.

```swift
//Import the jose-swift library
import JSONWebKey
import JSONWebToken
import JSONWebSignature
```

## Verifying a Signed JWT

To verify a signed JWT, you need the corresponding public key. Let's start with a JWT signed using a `P256` private key.

### Verifying with a P256 Public Key

Assume you have a JWT string and the corresponding public key.

```swift
// Extract the public key from the private key
// Replace with the pair public key
let publicKey = try P256.Signing.PublicKey(rawRepresentation: Data())

// JWT string to verify
let jwtString = "your.jwt.string"

// Verify the JWT
let jwt = try JWT.verify(jwtString: jwtString)
print("No errors so your JWT is verified: \(jwt.jwtString)")
```
Example 6.1

### Verifying with a SecKey

You can also verify a JWT using a `SecKey`.

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

// Extract the public key from the SecKey private key
let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!

// JWT string to verify
let jwtString = "your.jwt.string"

// Verify the JWT
let jwt = try JWT.verify(jwtString: jwtString, senderKey: secPublicKey)
print("No errors so your JWT is verified: \(jwt.jwtString)")
```
Example 6.2

### Verifying with a JWK

You can also verify a JWT using a JWK (JSON Web Key).

```swift
// Create a JWK
let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))

// JWT string to verify
let jwtString = "your.jwt.string"

// Verify the JWT
let jwt = try JWT.verify(jwtString: jwtString, senderKey: jwk)
print("No errors so your JWT is verified: \(jwt.jwtString)")
```
Example 6.3

## Additional Claims Verification

Besides verifying the signature, you might also want to verify specific claims, such as the issuer or audience.

### Verify Claims

Assume you have a JWT payload with claims and want to validate the issuer and audience.

```swift
// Define the expected issuer and audience
let expectedIssuer = "your-issuer"
let expectedAudience = "your-audience"

let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))
// The library verifies automatically iat, nbf and exp but you can pass values for iss, sub and aud
let jwt = try JWT.verify(jwtString: "your.jwt.here", senderKey: jwk, expectedIssuer: expectedIssuer, expectedAudience: expectedAudience)
print("No errors so your JWT is verified: \(jwt.jwtString)")
```
Example 6.4

That's it! You now know how to verify JWTs using different key types and validate specific claims using the **jose-swift** library.
