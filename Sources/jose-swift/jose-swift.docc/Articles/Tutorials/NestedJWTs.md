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
let payload = "Your payload data".data(using: .utf8)!
let protectedHeader = DefaultJWSHeaderImpl(algorithm: .HS256)
let key = SymmetricKey(size: .bits256) // Replace with your key

let jws = try JWS(payload: payload, protectedHeader: protectedHeader, key: key)
```

### Step 2: Encrypt the JWS

Next, encrypt the JWS to create a nested JWT:

```swift
let jweHeader = DefaultJWEHeaderImpl(
    keyManagementAlgorithm: .RSAOAEP256,
    encodingAlgorithm: .A256GCM
)
let rsaPublicKey = try SecKey.createPublicKey(from: rsaPublicKeyData) // Replace with your RSA public key data

let jwe = try JWE(
    payload: jws.compactSerialization.data(using: .utf8)!,
    protectedHeader: jweHeader,
    recipientKey: rsaPublicKey
)

let nestedJWT = jwe.compactSerialization
```

## Verifying a Nested JWT

To verify a nested JWT, you'll first decrypt the JWE to extract the embedded JWS, and then verify the signature of the JWS.

### Step 1: Decrypt the JWE

Decrypt the JWE to get the embedded JWS:

```swift
let jwe = try JWE(compactString: nestedJWT)
let rsaPrivateKey = try SecKey.createPrivateKey(from: rsaPrivateKeyData) // Replace with your RSA private key data

let decryptedPayload = try jwe.decrypt(recipientKey: rsaPrivateKey)
```

### Step 2: Verify the JWS

Verify the signature of the extracted JWS:

```swift
let jws = try JWS(compactString: String(data: decryptedPayload, encoding: .utf8)!)
let isValid = try jws.verify(key: key) // Replace with the key used for signing

if isValid {
    print("The nested JWT is valid.")
} else {
    print("The nested JWT is invalid.")
}
```
