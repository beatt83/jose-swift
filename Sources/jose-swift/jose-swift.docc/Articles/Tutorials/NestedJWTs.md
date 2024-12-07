# Creating and Verifying Nested JSON Web Tokens (JWTs)

Nested JWTs are used when you need to embed one JWT inside another. This can be useful for scenarios where you need to encrypt a signed JWT, providing an additional layer of security.

## Prerequisites

Ensure you have the **jose-swift** library installed and imported in your project.

```swift
//Import the jose-swift library
import JSONWebKey
import JSONWebToken
```

## Creating a Nested JWT

To create a nested JWT, you'll first sign the payload to create a JWS, and then encrypt the resulting JWS to create a JWE.

### Step 1: Sign the Payload

Start by signing the payload with the desired signing algorithm and key:

```swift
let innerJWTHeader = DefaultJWSHeaderImpl(algorithm: .ES256)

let p256SigningKey = P256.Signing.PrivateKey()
let jwt = try JWT.signed(
    claims: {
        IssuerClaim(value: "some-issuer")
    },
    protectedHeader: innerJWTHeader,
    key: p256SigningKey
)
```
Example 9.1

### Step 2: Encrypt the JWS

Next, encrypt the JWS to create a nested JWT:

```swift
let p384EncodingKey = P384.KeyAgreement.PrivateKey()

let outerJWTHeader = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .ecdhESA256KW,
    encodingAlgorithm: .a256GCM
)

let nestedJWT = try JWT.encryptAsNested(jwt: jwt, protectedHeader: outerJWTHeader, recipientKey: p384EncodingKey)
```
Example 9.2

## Verifying a Nested JWT

To verify a nested JWT, you'll first decrypt the JWE to extract the embedded JWS, and then verify the signature of the JWS.

The verify API decrupts and verifies the signature of the inner JWT and returns the Inner JWT:

```swift
let verifiedJWT = try JWT.verify(jwtString: nestedJWT.jwtString, recipientKey: p256EncodingKey, nestedKeys: [p256SigningKey])
print(try verifiedJWT.payload.tryToString())
```
Example 9.3
