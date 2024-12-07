# Encrypting JWTs

This guide demonstrates how to encrypt JSON Web Tokens (JWTs) using the `jose-swift` library. Encrypted JWTs (JWEs) ensure the confidentiality of the payload, protecting it from unauthorized access.

## Encrypting a JWT with a Symmetric Key

In this example, we'll encrypt a JWT using a symmetric key (a shared secret).

### Example

```swift
// Define the encryption key and header:
let cek = Data([
    177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
    212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
    234, 64, 252,
])
let header = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .direct,
    encodingAlgorithm: .a256GCM
)

// Encrypt the JWT:
let encryptedJWT = try JWT.encrypt(
    claims: {
        SubjectClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: header,
    senderKey: nil,
    recipientKey: nil,
    sharedKey: nil,
    cek: cek
)

// Output the encrypted JWT string:
print(encryptedJWT.jwtString)
```
Example 7.1

## Encrypting a JWT with an Asymmetric Key

This example demonstrates how to encrypt a JWT using an asymmetric key (e.g., RSA).

### Example

```swift
//Generate RSA key pair:
let privateKey = P256.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey

// Define the encryption key and header:
let header = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .ecdhESA256KW,
    encodingAlgorithm: .a256GCM
)

// Encrypt the JWT:
let encryptedJWT = try JWT.encrypt(
    claims: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: header,
    senderKey: nil,
    recipientKey: publicKey,
    sharedKey: nil
)

// Output the encrypted JWT string:
print(encryptedJWT.jwtString)
```
Example 7.2
