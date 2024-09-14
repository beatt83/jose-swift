# JWE Encryption

JSON Web Encryption (JWE) provides a mechanism for securely encrypting data, ensuring both confidentiality and integrity. This article explains the concepts behind JWE, how to create and decrypt encrypted payloads using the **jose-swift** library, and practical examples to get you started.

## What is a JWE?

A JSON Web Encryption (JWE) is a compact, URL-safe token format that represents encrypted content using JSON data structures. It is used to ensure the confidentiality of the data by encrypting the payload.

## Supported Algorithms

The **jose-swift** library supports a wide range of cryptographic algorithms for JSON Web Encryption (JWE). The supported algorithms are:

### Key Management Algorithms
- **RSA1_5**: RSAES-PKCS1-v1_5
- **RSA-OAEP**: RSAES OAEP using default parameters
- **RSA-OAEP-256**: RSAES OAEP using SHA-256 and MGF1 with SHA-256
- **A128KW**: AES Key Wrap with default 128-bit key
- **A192KW**: AES Key Wrap with 192-bit key
- **A256KW**: AES Key Wrap with 256-bit key
- **dir**: Direct use of a shared symmetric key
- **ECDH-ES**: Elliptic Curve Diffie-Hellman Ephemeral Static key agreement
- **ECDH-ES+A128KW**: ECDH-ES using Concat KDF and A128KW wrapping
- **ECDH-ES+A192KW**: ECDH-ES using Concat KDF and A192KW wrapping
- **ECDH-ES+A256KW**: ECDH-ES using Concat KDF and A256KW wrapping
- **ECDH-1PU**: Elliptic Curve Diffie-Hellman One-Pass Unified Model
- **ECDH-1PU+A128KW**: ECDH-1PU using Concat KDF and A128KW wrapping
- **ECDH-1PU+A192KW**: ECDH-1PU using Concat KDF and A192KW wrapping
- **ECDH-1PU+A256KW**: ECDH-1PU using Concat KDF and A256KW wrapping
- **A128GCMKW**: Key wrapping with AES GCM using 128-bit key
- **A192GCMKW**: Key wrapping with AES GCM using 192-bit key
- **A256GCMKW**: Key wrapping with AES GCM using 256-bit key
- **PBES2-HS256+A128KW**: PBES2 with HMAC SHA-256 and "A128KW" wrapping
- **PBES2-HS384+A192KW**: PBES2 with HMAC SHA-384 and "A192KW" wrapping
- **PBES2-HS512+A256KW**: PBES2 with HMAC SHA-512 and "A256KW" wrapping
- Note: ECDH-1PU is specified in [draft-ietf-jose-cfrg-curves-10](https://datatracker.ietf.org/doc/draft-ietf-jose-cfrg-curves/10/)

### Content Encryption Algorithms
- **A128CBC-HS256**: AES CBC using 128-bit key with HMAC SHA-256
- **A192CBC-HS384**: AES CBC using 192-bit key with HMAC SHA-384
- **A256CBC-HS512**: AES CBC using 256-bit key with HMAC SHA-512
- **A128GCM**: AES GCM using 128-bit key
- **A192GCM**: AES GCM using 192-bit key
- **A256GCM**: AES GCM using 256-bit key
- **C20P**: ChaCha20-Poly1305
- **XC20P**: XChaCha20-Poly1305
- Note: ChaChaPoly20-Poly1305 and XChaChaPoly20-Poly1305 is specified in [draft-amringer-jose-chacha-02](https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha-02)

### Compression Algorithms
- **DEFLATE**: (zip)

These algorithms provide flexibility in choosing the level of security and compatibility with different cryptographic standards. You can specify the algorithms to be used in the `alg` (key management algorithm) and `enc` (content encryption algorithm) fields of the JWE header when creating or decrypting a JWE.

## Structure of a JWE

A JWE is composed of five parts, separated by dots (`.`):

1. **Protected Header**
2. **Encrypted Key**
3. **Initialization Vector**
4. **Ciphertext**
5. **Authentication Tag**

### 1. Protected Header

The JWE protected header contains metadata about the encryption algorithm, key management algorithm, and other parameters. The header is Base64Url encoded.

Example:

```
{
    “alg”: “RSA-OAEP”,
    “enc”: “A256GCM”
}
```

### 2. Encrypted Key

The encrypted key is used to encrypt the Content Encryption Key (CEK). It is Base64Url encoded.

### 3. Initialization Vector

The initialization vector (IV) is used in the encryption process to provide randomness. It is Base64Url encoded.

### 4. Ciphertext

The ciphertext is the encrypted payload. It is Base64Url encoded.

### 5. Authentication Tag

The authentication tag is used to ensure the integrity and authenticity of the ciphertext. It is Base64Url encoded.

## Creating a JWE

Using the **jose-swift** library, creating a JWE is straightforward. Here’s an example of how to create a JWE:

```swift
let payload = “Hello, World!”.data(using: .utf8)!
let recipientKey = try RSA(publicKey: Data(base64Encoded: “your-public-key”)!)

let jwe = try JWE(
    payload: payload,
    keyManagementAlg: .rsaOAEP,
    encryptionAlgorithm: .a256GCM,
    recipientKey: recipientKey
)

print(“JWE: (jwe.compactSerialization)”)
```

In this example, the `JWE` initializer encrypts the payload using the RSA-OAEP key management algorithm and the A256GCM content encryption algorithm.

## Decrypting a JWE

To decrypt a JWE, you need to use the private key corresponding to the public key that was used to encrypt the token. Here’s an example:

```swift
let jweString = “your.jwe.token.here”
let recipientKey = try RSA(privateKey: Data(base64Encoded: “your-private-key”)!)
let jwe = try JWE(compactString: jweString)

let decryptedPayload = try jwe.decrypt(recipientKey: recipientKey)
print(“Decrypted payload: (String(data: decryptedPayload, encoding: .utf8)!)”)
```

In this example, the `decrypt` method decrypts the JWE using the private key.

## Using Custom Headers

You can include custom headers in your JWE to add additional metadata. Here’s an example:

```swift
let payload = “Hello, World!”.data(using: .utf8)!
let recipientKey = try RSA(publicKey: Data(base64Encoded: “your-public-key”)!)

var header = DefaultJWEHeaderImpl(keyManagementAlgorithm: .a256GCMKW, encodingAlgorithm: .a256GCM)
header.keyID = “key-id”

let jwe = try JWE(
    payload: payload,
    protectedHeader: header,
    recipientKey: recipientKey
)

print(“JWE: (jwe.compactSerialization)”)
```

In this example, the `kid` (key ID) field is added to the header to specify which key was used for encryption.

## Nested JWE

A Nested JWE is a JWE that is encrypted and then encrypted again. This provides an additional layer of security by ensuring both the confidentiality and authenticity of the message. Here’s how to create a nested JWE:

```swift
let nestedPayload = “Nested payload”.data(using: .utf8)!
let nestedRecipientKey = try RSA(publicKey: Data(base64Encoded: “nested-public-key”)!)

let nestedJwe = try JWE(
    payload: nestedPayload,
    keyManagementAlg: .rsaOAEP,
    encryptionAlgorithm: .a256GCM,
    recipientKey: nestedRecipientKey
)

let outerRecipientKey = try RSA(publicKey: Data(base64Encoded: “outer-public-key”)!)
let outerJwe = try JWE(
    payload: JSONEncoder().encode(nestedJwe.compactSerialization),
    keyManagementAlg: .rsaOAEP,
    encryptionAlgorithm: .a256GCM,
    recipientKey: outerRecipientKey
)

print(“Nested JWE: (outerJwe.compactSerialization)”)
```

## Conclusion

JSON Web Encryption (JWE) is a powerful way to ensure the confidentiality of your data. The **jose-swift** library provides robust support for creating and decrypting JWEs, including custom headers and nested tokens. Explore the tutorials and reference documentation to learn more about how to leverage JWE in your applications.

## Topics

### Supported Key Management Algorithms

- ``KeyManagementAlgorithm``

### Supported Content Encryption Algorithms

- ``ContentEncryptionAlgorithm``

### Supported Compression Algorithms

- ``ContentCompressionAlgorithm``
