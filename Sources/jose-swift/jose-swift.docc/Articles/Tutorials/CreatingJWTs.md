# Creating JSON Web Tokens (JWTs)

This guide will walk you through creating JSON Web Tokens (JWTs) using the **jose-swift** library. JWTs are a compact, URL-safe means of representing claims to be transferred between two parties. They can be signed to ensure integrity and authenticity.

## Defining the Claims

Claims are the pieces of information you want to include in the JWT. They are represented as a Codable struct in Swift.

```swift
Define the claims
struct MyClaims: JWTRegisteredFieldsClaims, Codable {
    var iss: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    let sub: String?
    let name: String
    
    init(
        iss: String? = nil,
        aud: [String]? = nil,
        exp: Date? = nil,
        nbf: Date? = nil,
        iat: Date? = nil,
        jti: String? = nil,
        sub: String? = nil,
        name: String
    ) {
        self.iss = iss
        self.aud = aud
        self.exp = exp
        self.nbf = nbf
        self.iat = iat
        self.jti = jti
        self.sub = sub
        self.name = name
    }
}

let _ = MyClaims(iat: Date(), sub: "1234567890", name: "John Doe")
```
Example 5.1

Or you can use the library DSL.

```swift
try JWT.signed(
    claims: {
        // Define the claims
        SujectbClaim(value: "1234567890")
        IssuedAtClaim(value: Date())
        StringClaim(key: "name", value: "John Doe")
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: privateKey
)
```
Example 5.2

## Creating and Signing a JWT

To create and sign a JWT, you need a private key. We'll use a `P256` private key for this example.

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
```
Example 5.3

## Inspecting the JWT

You can inspect the components of the JWT:

```swift
// Print the JWT string
print(jwt.jwtString)

// Print the JWT payload
print(jwt.payload)
```
Example 5.4

## Verifying a JWT

To verify a JWT, you need the corresponding public key. Extract the public key from the private key and use it to verify the JWT.

```swift
// Extract the public key
let publicKey = privateKey.publicKey

// Verify the JWT
let isValid = try JWT.verify(jwtString: "jwt-string", senderKey: publicKey)
print("JWT is valid: \(isValid)")
```
Example 5.5

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
    claims: {
        IssuerClaim(value: "some-issuer")
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: secPrivateKey
)

// Verify the JWT using SecKey
let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!
let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: secPublicKey)
print("JWT is valid: \(isValid)")
```
Example 5.6

## Using a JWK for Signing and Verification

You can also use a JWK (JSON Web Key) for signing and verifying JWTs.

```swift
// Create a JWK
let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))

// Sign a JWT using JWK
let jwt = try JWT.signed(
    claims: {
        IssuerClaim(value: "some-issuer")
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
    key: jwk
)

// Verify the JWT using JWK
let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: jwk)
print("JWT is valid: \(isValid)")
```
Example 5.7

That's it! You now know how to create, sign, inspect, and verify JWTs using the **jose-swift** library.
