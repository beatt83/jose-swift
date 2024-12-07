# JWS Signatures

JSON Web Signatures (JWS) provide a mechanism for digitally signing data, ensuring both the integrity and authenticity of the data. This article delves into the concepts behind JWS, how to create and verify signatures using the **jose-swift** library, and practical examples to help you get started.

## What is a JWS?

A JSON Web Signature (JWS) is a compact, URL-safe token format that represents signed content using JSON data structures. It is used to ensure the integrity and authenticity of the message by applying a digital signature or MAC (Message Authentication Code).

## Supported Algorithms

The **jose-swift** library supports a wide range of cryptographic algorithms for signing and verifying JSON Web Signatures (JWS). The supported algorithms are:

- **RS256**: RSA Signature with SHA-256
- **RS384**: RSA Signature with SHA-384
- **RS512**: RSA Signature with SHA-512
- **HS256**: HMAC with SHA-256
- **HS384**: HMAC with SHA-384
- **HS512**: HMAC with SHA-512
- **ES256**: ECDSA using P-256 and SHA-256
- **ES384**: ECDSA using P-384 and SHA-384
- **ES512**: ECDSA using P-521 and SHA-512
- **ES256K**: ECDSA using secp256k1 and SHA-256
- **PS256**: RSA PSS with SHA-256
- **PS384**: RSA PSS with SHA-384
- **PS512**: RSA PSS with SHA-512
- **EdDSA**: EdDSA using Ed25519 ([RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037))

These algorithms provide flexibility in choosing the level of security and compatibility with different cryptographic standards. You can specify the algorithm to be used in the `alg` field of the JWS header when creating or verifying a JWS.

## Structure of a JWS

A JWS is composed of three parts, separated by dots (`.`):

1. **Header**
2. **Payload**
3. **Signature**

### 1. Header

The JWS header contains metadata about the signature, including the algorithm used for signing and the type of token. The header is Base64Url encoded.

Example:

```
{
    “alg”: “HS256”,
    “typ”: “JWT”
}
```

### 2. Payload

The payload is the data being protected, typically containing the claims. The payload is also Base64Url encoded.

Example:

```
{
    “sub”: “1234567890”,
    “name”: “John Doe”,
    “admin”: true
}
```

### 3. Signature

The signature is created by signing the Base64Url encoded header and payload using the specified algorithm and a secret or private key.

For example, with HMAC SHA256, the signature is created as follows:

```
HMACSHA256(base64UrlEncode(header) + “.” + base64UrlEncode(payload),secret)
```

## Creating a JWS

Using the **jose-swift** library, creating a JWS is straightforward. Here’s an example of how to create a signed JWT, which is a specific type of JWS:

```swift
let key = P256.Signing.PrivateKey()
let payload = “Hello, World!”.data(using: .utf8)!

let header = DefaultJWSHeaderImpl(algorithm: .ES256)
let jws = try JWS(
    payload: payload,
    protectedHeader: header,
    key: key
)

print("JWS: \(jws.compactSerialization)")
```
Example 2.1

In this example, the `JWS` initializer generates a signed JWS using the ES256 algorithm and the provided private key.

## Verifying a JWS

To verify a JWS, you need to use the public key corresponding to the private key that was used to sign the token. Here’s an example:

```swift
let jwsString = “your.jws.token.here”
let publicKey = P256.Signing.PublicKey()
let jws = try JWS(jwsString: jwsString)

let isValid = try jws.verify(key: publicKey)
print("Signature is valid: \(isValid)")
```
Example 2.2

In this example, the `verify` method verifies the JWS using the public key.

## Using Custom Headers

You can include custom headers in your JWS to add additional metadata. Here’s an example:

```swift
let key = try secp256k1.Signing.PrivateKey()
let payload = "Hello, World!".data(using: .utf8)!

var header = DefaultJWSHeaderImpl(algorithm: .ES256K)
header.keyID = "key-id"

let jws = try JWS(
    payload: payload,
    protectedHeader: header,
    key: key
)

print("JWS: \(jws.compactSerialization)")
```
Example 2.3

In this example, the `kid` (key ID) field is added to the header to specify which key was used for signing.

## Nested JWS

A Nested JWS is a JWS that is signed and then signed again. This provides an additional layer of security by ensuring both the integrity and authenticity of the message. Here’s how to create a nested JWS:

```swift
let nestedKey = try RSA(keySize: 1228)
let nestedPayload = "Nested payload".data(using: .utf8)!

let nestedHeader = DefaultJWSHeaderImpl(algorithm: .RS512)
let nestedJws = try JWS(
    payload: nestedPayload,
    protectedHeader: nestedHeader,
    key: nestedKey
)

let outerKey = P521.Signing.PrivateKey()
let outerHeader = DefaultJWSHeaderImpl(algorithm: .ES512, contentType: "JWT")
let outerJws = try JWS(
    payload: JSONEncoder().encode(nestedJws.compactSerialization),
    protectedHeader: outerHeader,
    key: outerKey
)

print("Nested JWS: \(outerJws.compactSerialization)")
```
Example 2.4

## Conclusion

JSON Web Signatures (JWS) are a powerful way to ensure the integrity and authenticity of your data. The **jose-swift** library provides robust support for creating and verifying JWS, including custom headers and nested tokens. Explore the tutorials and reference documentation to learn more about how to leverage JWS in your applications.

## Topics

### Supported Signatures

- ``SigningAlgorithm``
- ``HS256Signer``
- ``HS256Verifier``
- ``HS384Signer``
- ``HS384Verifier``
- ``HS512Signer``
- ``HS512Verifier``
- ``ES256Signer``
- ``ES256Verifier``
- ``ES384Signer``
- ``ES384Verifier``
- ``ES512Signer``
- ``ES521Verifier``
- ``ES256KSigner``
- ``ES256KVerifier``
- ``EdDSASigner``
- ``EdDSAVerifier``
- ``RS256Signer``
- ``RS256Verifier``
- ``RS384Signer``
- ``RS384Verifier``
- ``RS512Signer``
- ``RS512Verifier``
- ``PS256Signer``
- ``PS256Verifier``
- ``PS384Signer``
- ``PS384Verifier``
- ``PS512Signer``
- ``PS512Verifier``
