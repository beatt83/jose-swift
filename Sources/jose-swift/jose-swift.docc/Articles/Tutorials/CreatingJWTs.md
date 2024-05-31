# Creating JSON Web Tokens (JWTs)

This guide will walk you through creating JSON Web Tokens (JWTs) using the **jose-swift** library. JWTs are a compact, URL-safe means of representing claims to be transferred between two parties. They can be signed to ensure integrity and authenticity.

## Defining the Claims

Claims are the pieces of information you want to include in the JWT. They are represented as a Codable struct in Swift.

```swift
Define the claims
struct MyClaims: JWTRegisteredFieldsClaims, Codable {
    let sub: String?
    let name: String
    let iat: Int?
}

let claims = MyClaims(sub: "1234567890", name: "John Doe", iat: 1516239022)
```

Or you can use the library DSL.

```swift
let jsonClaimsObject = JWTClaimsBuilder.build {
    SubClaim(value: "1234567890")
    IatClaim(value: Date())
    StringClaim(key: "name", value: "John Doe")
}
```

## Creating and Signing a JWT

To create and sign a JWT, you need a private key. We'll use a `P256` private key for this example.

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

## Inspecting the JWT

You can inspect the components of the JWT:

```swift
// Print the JWT string
print(jwt.jwtString)

// Print the JWT header and payload
print(jwt.header)
print(jwt.payload)
```

## Verifying a JWT

To verify a JWT, you need the corresponding public key. Extract the public key from the private key and use it to verify the JWT.

```swift
// Extract the public key
let publicKey = privateKey.publicKey

// Verify the JWT
let isValid = try jwt.verify(key: publicKey)
print("JWT is valid: \(isValid)")
```

## Using a SecKey for Signing and Verification

You can also use `SecKey` for signing and verifying JWTs.

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

// Sign a JWT using SecKey
let jwt = try JWT.signed(
    payload: claims,
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: secPrivateKey
)

// Verify the JWT using SecKey
let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!
let isValid = try jwt.verify(key: secPublicKey)
print("JWT is valid: \(isValid)")
```

## Using a JWK for Signing and Verification

You can also use a JWK (JSON Web Key) for signing and verifying JWTs.

```swift
// Create a JWK
let jwk = JWK(octetSequence: Data(repeating: 0, count: 32))

// Sign a JWT using JWK
let jwt = try JWT.signed(
    payload: claims,
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
    key: jwk
)

// Verify the JWT using JWK
let isValid = try jwt.verify(key: jwk)
print("JWT is valid: \(isValid)")
```

That's it! You now know how to create, sign, inspect, and verify JWTs using the **jose-swift** library.
