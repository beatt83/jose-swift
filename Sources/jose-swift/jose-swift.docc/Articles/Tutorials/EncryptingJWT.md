# Encrypting JWTs

This guide demonstrates how to encrypt JSON Web Tokens (JWTs) using the `jose-swift` library. Encrypted JWTs (JWEs) ensure the confidentiality of the payload, protecting it from unauthorized access.

## Encrypting a JWT with a Symmetric Key

In this example, we'll encrypt a JWT using a symmetric key (a shared secret).

### Example

```swift
// Define the encryption key and header:
let symmetricKey = Data("your-256-bit-secret".utf8)
let header = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .direct,
    encodingAlgorithm: .A256GCM
)

// Encrypt the JWT:
let encryptedJWT = try JWT.encrypt(
    payload: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin": value: true)
    },
    protectedHeader: header,
    unprotectedHeader: nil,
    senderKey: nil,
    recipientKey: symmetricKey,
    sharedKey: nil
)

// Output the encrypted JWT string:
print(encryptedJWT.jwtString)
```

## Encrypting a JWT with an Asymmetric Key

This example demonstrates how to encrypt a JWT using an asymmetric key (e.g., RSA).

### Example

```swift
//Generate RSA key pair:
let privateKey = try RSA.generate(bits: 2048)
let publicKey = privateKey.publicKey

// Define the encryption key and header:
let header = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .rsaOAEP,
    encodingAlgorithm: .A256GCM
)

// Encrypt the JWT:
let encryptedJWT = try JWT.encrypt(
    payload: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin": value: true)
    },
    protectedHeader: header,
    unprotectedHeader: nil,
    senderKey: nil,
    recipientKey: publicKey,
    sharedKey: nil
)

// Output the encrypted JWT string:
print(encryptedJWT.jwtString)
```
