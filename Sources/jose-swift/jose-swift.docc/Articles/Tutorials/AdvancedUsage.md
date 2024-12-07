# Advanced Usage

In this section, we will cover advanced usage scenarios for the `jose-swift` library, including custom headers, nested JWTs, and encryption.

## Custom Headers

The `jose-swift` library allows you to create and use custom headers in your JWTs.

### Custom JWS Header Example

Define a custom JWS header:

```swift
struct CustomHeader: JWSRegisteredFieldsHeader {
    var algorithm: SigningAlgorithm?
    var jwkSetURL: String?
    var jwk: JWK?
    var keyID: String?
    var x509URL: String?
    var x509CertificateChain: String?
    var x509CertificateSHA1Thumbprint: String?
    var x509CertificateSHA256Thumbprint: String?
    var type: String?
    var contentType: String?
    var critical: String?
    var customField: String?
}
```

Create a signed JWT with the custom header:

```swift
let customHeader = CustomHeader(
    algorithm: .HS256,
    customField: "customValue"
)

let signedJWT = try JWT.signed(
    claims: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: customHeader,
    key: Data("your-256-bit-secret".utf8)
)
```

### Custom JWE Header Example

Define a custom JWE header:

```swift
struct CustomJWEHeader: JWERegisteredFieldsHeader {
    var keyManagementAlgorithm: KeyManagementAlgorithm?
    var encodingAlgorithm: ContentEncryptionAlgorithm?
    var compressionAlgorithm: ContentCompressionAlgorithm?
    var jwkSetURL: String?
    var jwk: JWK?
    var keyID: String?
    var x509URL: String?
    var x509CertificateChain: String?
    var x509CertificateSHA1Thumbprint: String?
    var x509CertificateSHA256Thumbprint: String?
    var type: String?
    var contentType: String?
    var critical: String?
    var senderKeyID: String?
    var customField: String?
}
```

Create an encrypted JWT with the custom header:

```swift
let customJWEHeader = CustomJWEHeader(
    keyManagementAlgorithm: .RSA_OAEP,
    encodingAlgorithm: .A256GCM,
    customField: "customValue"
)

let encryptedJWT = try JWE(
    claims: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: customJWEHeader,
    recipientKey: rsaPublicKey
)
```

## Nested JWTs

Nested JWTs allow you to create a JWT that contains another JWT as its payload. This can be useful for scenarios where you need multiple layers of security.

### Example

Create and sign an inner JWT:

```swift
let innerJWT = try JWT.signed(
    claims: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
    key: Data("your-256-bit-secret".utf8)
)

// Create and sign an outer JWT that contains the inner JWT
let outerJWT = try JWT.signedAsNested(
    jwtString: innerJWT.jwtString,
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .RS256),
    key: rsaPrivateKey
)
```

## Encryption

The `jose-swift` library supports encrypting JWTs to provide confidentiality.

### Example

Encrypt a JWT:

```swift
let encryptedJWT = try JWT.encrypt(
    claims: {
        SubClaim(value: "1234567890")
        StringClaim(key: "name", value: "John Doe")
        BoolClaim(key: "admin", value: true)
    },
    protectedHeader: DefaultJWEHeaderImpl(
        keyManagementAlgorithm: .rsaOAEP,
        encryptionAlgorithm: .A256GCM
    ),
    recipientKey: rsaPublicKey
)

// Output the encrypted JWT string:

print(encryptedJWT.jwtString)
```

By using these advanced features, you can create more secure and flexible JWTs tailored to your specific requirements.
