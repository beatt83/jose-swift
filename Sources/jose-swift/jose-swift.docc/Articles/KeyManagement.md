# Key Management

Key management is a critical aspect of securing JSON Web Tokens (JWTs) and JSON Web Encryption (JWE). It involves the creation, distribution, storage, and rotation of cryptographic keys used for signing and encrypting tokens. This article provides an overview of key management concepts and demonstrates how to handle key management using the **jose-swift** library.

## Overview of Key Management

Key management involves various tasks to ensure the security and integrity of cryptographic keys used in JWT and JWE. These tasks include:

1. **Key Generation**: Creating secure cryptographic keys.
2. **Key Distribution**: Safely distributing keys to authorized parties.
3. **Key Storage**: Storing keys securely to prevent unauthorized access.
4. **Key Rotation**: Regularly updating keys to minimize the risk of key compromise.
5. **Key Revocation**: Invalidating keys that are no longer secure.

## Supported Key Types

The **jose-swift** library supports various types of cryptographic keys for signing and encryption. The key types include:

### Signing Keys

- P256.Signing.PrivateKey
- P256.Signing.PublicKey
- P384.Signing.PrivateKey
- P384.Signing.PublicKey
- P521.Signing.PrivateKey
- P521.Signing.PublicKey
- Curve25519.Signing.PrivateKey
- Curve25519.Signing.PublicKey
- secp256k1.Signing.PrivateKey
- secp256k1.Signing.PublicKey

### Key Agreement Keys

- P256.KeyAgreement.PrivateKey
- P256.KeyAgreement.PublicKey
- P384.KeyAgreement.PrivateKey
- P384.KeyAgreement.PublicKey
- P521.KeyAgreement.PrivateKey
- P521.KeyAgreement.PublicKey
- Curve25519.KeyAgreement.PrivateKey
- Curve25519.KeyAgreement.PublicKey
- secp256k1.KeyAgreement.PrivateKey
- secp256k1.KeyAgreement.PublicKey

### Other Key Types

- RSA PrivateKey
- RSA PublicKey

Note: `Data` key types are available only for signatures and require that the header provides the `alg` being used.

## KeyRepresentable Protocol

The **jose-swift** library introduces the `KeyRepresentable` protocol, which allows various key types to be used interchangeably in the API. The protocol ensures that any key can be represented as a `JWK` (JSON Web Key).

The `KeyRepresentable` protocol is supported by several key types, including `JWK`, `RSA`, `Curve25519`, `P256`, `P384`, `P521`, and `secp256k1` keys. This allows you to use any of these types seamlessly with the **jose-swift** library.

## Examples

### Signing with Different Key Types

You can use different types of keys to sign a payload using JWS. Here's an example of how to sign a payload with a P256 signing key:

```swift
let payload = Data("Your payload data".utf8)
let privateKey = try P256.Signing.PrivateKey()
let header = DefaultJWSHeaderImpl(algorithm: .ES256)

let jws = try JWS(payload: payload, protectedHeader: header, key: privateKey)
```

Similarly, you can sign with other key types such as RSA and Curve25519.

### Signing with `SecKey`

The following example demonstrates how to sign a payload using a `SecKey`:

```swift
let payload = Data("Your payload data".utf8)
let privateKey: SecKey = // Your SecKey initialization
let header = DefaultJWSHeaderImpl(algorithm: .RS256)

let jws = try JWS(payload: payload, protectedHeader: header, key: privateKey)
```

### Signing with `JWK` Octet Sequence

Here is an example of how to sign a payload using a `JWK` octet sequence:

```swift
let payload = Data("Your payload data".utf8)
let jwk = JWK(octetSequence: Data("your-octet-sequence".utf8))
let header = DefaultJWSHeaderImpl(algorithm: .HS256)

let jws = try JWS(payload: payload, protectedHeader: header, key: jwk)
```

### Encrypting with Different Key Types

You can use different types of keys to encrypt a payload using JWE. Here's an example of how to encrypt a payload with a P256 key agreement key:

```swift
let payload = Data("Your payload data".utf8)
let recipientKey = try P256.KeyAgreement.PublicKey()
let encryptionAlgorithm = ContentEncryptionAlgorithm.A256GCM
let keyManagementAlgorithm = KeyManagementAlgorithm.ecdhES

let jwe = try JWE(
    payload: payload,
    keyManagementAlg: keyManagementAlgorithm,
    encryptionAlgorithm: encryptionAlgorithm,
    recipientKey: recipientKey
)
```

## Conclusion

Proper key management is essential for ensuring the security of JWTs and JWEs. The **jose-swift** library provides flexible support for various key types and allows seamless integration of these keys into your cryptographic operations. By leveraging the `KeyRepresentable` protocol, you can easily manage and utilize different key types in your applications.
