# JWT Concepts

JSON Web Tokens (JWTs) are a compact, URL-safe means of representing claims to be transferred between two parties. They are commonly used for authentication and information exchange in web applications. This article covers the fundamental concepts of JWTs, their structure, and how they are used in the **jose-swift** library.

## What is a JWT?

A JWT is a JSON object that is used to securely transmit information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with HMAC algorithm) or a public/private key pair (with RSA or ECDSA).

## Structure of a JWT

A JWT consists of three parts separated by dots (`.`):

1. **Header**
2. **Payload**
3. **Signature**

### 1. Header

The header typically consists of two parts: the type of the token, which is JWT, and the signing algorithm being used, such as HMAC SHA256 or RSA.

Example:

```
{
    “alg”: “HS256”,
    “typ”: “JWT”
}
```

### 2. Payload

The payload contains the claims. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: registered, public, and private claims.

Example:

```
{
    “sub”: “1234567890”,
    “name”: “John Doe”,
    “admin”: true
}
```

### 3. Signature

To create the signature part, you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.

For example, if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(base64UrlEncode(header) + “.” + base64UrlEncode(payload),secret)
```

## How JWTs Work

When a user logs in, the server generates a JWT and sends it to the client. The client stores the JWT (usually in local storage or a cookie) and includes it in the Authorization header of subsequent requests. The server then verifies the token's signature to authenticate the user and grants access to protected resources.

## Types of JWTs

### Signed JWTs (JWS)

A signed JWT (JSON Web Signature) is used to ensure the integrity and authenticity of the token. The signature is created using a secret or a private key.

### Encrypted JWTs (JWE)

An encrypted JWT (JSON Web Encryption) is used to ensure the confidentiality of the token. The payload is encrypted using a public key or a shared secret.

## JWT Claims

JWT claims are pieces of information asserted about a subject. There are several types of claims:

- **Registered Claims**: Predefined claims that provide a set of useful, interoperable claims. Examples include `iss` (issuer), `exp` (expiration time), `sub` (subject), and `aud` (audience).
- **Public Claims**: Custom claims that are agreed upon and shared with all parties using the JWTs.
- **Private Claims**: Custom claims created to share information between parties that agree on using them and are not registered or public.

## Using JWTs with **jose-swift**

### Creating a JWT

Here's an example of how to create a signed JWT using the **jose-swift** library:

```swift
let key = P256.Signing.PrivateKey()
let jwt = try JWT.signed(
    payload: {
        IssuerClaim(value: “your-issuer”)
        SubjectClaim(value: “your-subject”)
        ExpirationTimeClaim(value: Date().addingTimeInterval(3600)) // 1 hour expiration
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: key.jwkRepresentation
)

print(“JWT: (jwt.jwtString)”)
```

### Verifying a JWT

Here's an example of how to verify a JWT using the **jose-swift** library:

```swift
let jwtString = “your.jwt.token.here”
let key = P256.Signing.PublicKey()
let verifiedJWT = try JWT.verify(jwtString: jwtString, signerKey: key)

print(“Verified JWT Payload: (verifiedJWT.payload)”)
```

### Using Custom Claims

You can also define and use custom claims in your JWTs. Here's an example:

```swift
struct CustomClaims: JWTRegisteredFieldsClaims, Codable {
    let iss: String?
    let sub: String?
    let aud: [String]?
    let exp: Date?
    let nbf: Date?
    let iat: Date?
    let jti: String?
    let customClaim: String
}

let key = P256.Signing.PrivateKey()
let claims = CustomClaims(iss: “your-issuer”, sub: “your-subject”, custom: “custom-value”)

let jwt = try JWT.signed(
    payload: claims,
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: key
)
```

Or through the DSL API. Here's an example:

```swift
let jwt = try JWT.signed(
    payload: {
        IssuerClaim(value: “your-issuer”)
        SubjectClaim(value: “your-subject”)
        ExpirationTimeClaim(value: Date().addingTimeInterval(3600)) // 1 hour expiration
        ObjectClaim(key: "address") {
            StringClaim(key: "street", value: "Rua Sesamo")
            NumberClaim(key: "buildingNumber", value: 1)
            BoolClaim(key: "isBuilding", value: true)
        }
        ArrayClaim(key: "nickNames") {
            .string("Me")
            .string("Myself")
            .string("I")
        }
    },
    protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
    key: key.jwkRepresentation
)
```

## Conclusion

JWTs are a powerful and flexible way to securely transmit information between parties. The **jose-swift** library provides a comprehensive set of tools for working with JWTs, including support for signing, verification, and custom claims. Explore the tutorials and reference documentation to learn more about how to use this library in your projects.
