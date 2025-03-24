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

>Warning: If you create a custom header you will need to conform with the codable extension and you need to provide correct coding keys and formats for the parameters,
you can copy/paste the following code and add your custom parameters:

For `JWSRegisteredFieldsHeader`:

```swift
extension CustomHeader: Codable {
    enum CodingKeys: String, CodingKey {
        case algorithm = "alg"
        case jwkSetURL = "jku"
        case jwk
        case keyID = "kid"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
        case type = "typ"
        case contentType = "cty"
        case critical = "crit"
        case initializationVector = "iv"
        case authenticationTag = "tag"
        case ephemeralPublicKey = "epk"
        case agreementPartyUInfo = "apu"
        case agreementPartyVInfo = "apv"
        case pbes2SaltInput = "p2s"
        case pbes2Count = "p2c"
        case senderKeyID = "skid"
        case base64EncodedUrlPayload = "b64"
        // ... add your custom parameters here
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(algorithm, forKey: .algorithm)
        try container.encodeIfPresent(jwkSetURL, forKey: .jwkSetURL)
        try container.encodeIfPresent(jwk, forKey: .jwk)
        try container.encodeIfPresent(keyID, forKey: .keyID)
        try container.encodeIfPresent(x509URL, forKey: .x509URL)
        try container.encodeIfPresent(x509CertificateChain, forKey: .x509CertificateChain)
        try container.encodeIfPresent(x509CertificateSHA1Thumbprint, forKey: .x509CertificateSHA1Thumbprint)
        try container.encodeIfPresent(x509CertificateSHA256Thumbprint, forKey: .x509CertificateSHA256Thumbprint)
        try container.encodeIfPresent(type, forKey: .type)
        try container.encodeIfPresent(contentType, forKey: .contentType)
        try container.encodeIfPresent(critical, forKey: .critical)
        try container.encodeIfPresent(base64EncodedUrlPayload, forKey: .base64EncodedUrlPayload)
        // ... add your custom parameters encoding here
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        algorithm = try container.decodeIfPresent(SigningAlgorithm.self, forKey: .algorithm)
        jwkSetURL = try container.decodeIfPresent(String.self, forKey: .jwkSetURL)
        jwk = try container.decodeIfPresent(JWK.self, forKey: .jwk)
        keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
        x509URL = try container.decodeIfPresent(String.self, forKey: .x509URL)
        x509CertificateChain = try container.decodeIfPresent([String].self, forKey: .x509CertificateChain)
        x509CertificateSHA1Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA1Thumbprint)
        x509CertificateSHA256Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA256Thumbprint)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
        critical = try container.decodeIfPresent([String].self, forKey: .critical)
        base64EncodedUrlPayload = try container.decodeIfPresent(Bool.self, forKey: .base64EncodedUrlPayload)
        // ... add your custom parameters decoding here
    }
}
```

For `JWERegisteredFieldsHeader`:

```swift
extension DefaultJWEHeaderImpl: Codable {
    enum CodingKeys: String, CodingKey {
        case keyManagementAlgorithm = "alg"
        case encodingAlgorithm = "enc"
        case compressionAlgorithm = "zip"
        case jwkSetURL = "jku"
        case jwk
        case keyID = "kid"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
        case type = "typ"
        case contentType = "cty"
        case critical = "crit"
        case initializationVector = "iv"
        case authenticationTag = "tag"
        case ephemeralPublicKey = "epk"
        case agreementPartyUInfo = "apu"
        case agreementPartyVInfo = "apv"
        case pbes2SaltInput = "p2s"
        case pbes2Count = "p2c"
        case senderKeyID = "skid"
        // ... add your custom parameters here
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(keyManagementAlgorithm, forKey: .keyManagementAlgorithm)
        try container.encodeIfPresent(encodingAlgorithm, forKey: .encodingAlgorithm)
        try container.encodeIfPresent(compressionAlgorithm, forKey: .compressionAlgorithm)
        try container.encodeIfPresent(jwkSetURL, forKey: .jwkSetURL)
        try container.encodeIfPresent(jwk, forKey: .jwk)
        try container.encodeIfPresent(keyID, forKey: .keyID)
        try container.encodeIfPresent(x509URL, forKey: .x509URL)
        try container.encodeIfPresent(x509CertificateChain, forKey: .x509CertificateChain)
        try container.encodeIfPresent(x509CertificateSHA1Thumbprint, forKey: .x509CertificateSHA1Thumbprint)
        try container.encodeIfPresent(x509CertificateSHA256Thumbprint, forKey: .x509CertificateSHA256Thumbprint)
        try container.encodeIfPresent(ephemeralPublicKey, forKey: .ephemeralPublicKey)
        try container.encodeIfPresent(type, forKey: .type)
        try container.encodeIfPresent(contentType, forKey: .contentType)
        try container.encodeIfPresent(critical, forKey: .critical)
        try initializationVector.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .initializationVector)
        }
        try authenticationTag.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .authenticationTag)
        }
        try agreementPartyUInfo.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .agreementPartyUInfo)
        }
        try agreementPartyVInfo.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .agreementPartyVInfo)
        }
        try pbes2SaltInput.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .pbes2SaltInput)
        }
        try container.encodeIfPresent(pbes2SaltCount, forKey: .pbes2Count)
        try container.encodeIfPresent(senderKeyID, forKey: .senderKeyID)
        // ... add your custom parameters encoding here
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyManagementAlgorithm = try container.decodeIfPresent(KeyManagementAlgorithm.self, forKey: .keyManagementAlgorithm)
        encodingAlgorithm = try container.decodeIfPresent(ContentEncryptionAlgorithm.self, forKey: .encodingAlgorithm)
        compressionAlgorithm = try container.decodeIfPresent(ContentCompressionAlgorithm.self, forKey: .compressionAlgorithm)
        jwkSetURL = try container.decodeIfPresent(String.self, forKey: .jwkSetURL)
        jwk = try container.decodeIfPresent(JWK.self, forKey: .jwk)
        keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
        x509URL = try container.decodeIfPresent(String.self, forKey: .x509URL)
        x509CertificateChain = try container.decodeIfPresent([String].self, forKey: .x509CertificateChain)
        x509CertificateSHA1Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA1Thumbprint)
        x509CertificateSHA256Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA256Thumbprint)
        ephemeralPublicKey = try container.decodeIfPresent(JWK.self, forKey: .ephemeralPublicKey)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
        critical = try container.decodeIfPresent([String].self, forKey: .critical)
        senderKeyID = try container.decodeIfPresent(String.self, forKey: .senderKeyID)
        let initializationVectorBase64Url = try container.decodeIfPresent(String.self, forKey: .initializationVector)
        initializationVector = try initializationVectorBase64Url.map { try Base64URL.decode($0) }
        let autheticationTagBase64Url = try container.decodeIfPresent(String.self, forKey: .authenticationTag)
        authenticationTag = try autheticationTagBase64Url.map { try Base64URL.decode($0) }
        let partyUInfoBase64Url = try container.decodeIfPresent(String.self, forKey: .agreementPartyUInfo)
        agreementPartyUInfo = try partyUInfoBase64Url.map { try Base64URL.decode($0) }
        let partyVInfoBase64Url = try container.decodeIfPresent(String.self, forKey: .agreementPartyVInfo)
        agreementPartyVInfo = try partyVInfoBase64Url.map { try Base64URL.decode($0) }
        let pbes2SaltInputBase64Url = try container.decodeIfPresent(String.self, forKey: .pbes2SaltInput)
        pbes2SaltInput = try pbes2SaltInputBase64Url.map { try Base64URL.decode($0) }
        pbes2SaltCount = try container.decodeIfPresent(Int.self, forKey: .pbes2Count)
        // ... add your custom parameters decoding here
    }
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
