# Custom Claims in JWTs

Custom claims allow you to include additional information in your JSON Web Tokens (JWTs). These claims can carry various types of data relevant to your application's needs.

## Prerequisites

Ensure you have the **jose-swift** library installed and imported in your project.

## Defining Custom Claims

Define your custom claims by creating a struct that conforms to the `Codable` and `JWTRegisteredFieldsClaims` protocol:

```swift
struct CustomClaims: Codable {
    let iss: String?
    let sub: String?
    let aud: [String]?
    let exp: Date?
    let nbf: Date?
    let iat: Date?
    let jti: String?
    let userId: String
    let roles: [String]
}
```

## Creating a JWT with Custom Claims

To create a JWT with custom claims, you need to include your custom claims in the payload and sign the JWT.

### Step 1: Create the Payload

Create an instance of your custom claims struct:

```swift
let customClaims = CustomClaims(
    exp: Date().addingTimeInterval(3600), // 1 hour expiration
    userId: "12345",
    roles: ["admin", "user"]
)
```

### Step 2: Sign the JWT

Sign the JWT using your custom claims as the payload:

```swift
let protectedHeader = DefaultJWSHeaderImpl(algorithm: .HS256)
let key = SymmetricKey(size: .bits256) // Replace with your key

let jwt = try JWT.signed(
    payload: customClaims,
    protectedHeader: protectedHeader,
    key: key
)

print("Signed JWT: \(jwt.jwtString)")
```

## Verifying a JWT with Custom Claims

To verify a JWT with custom claims, decode the JWT and extract the claims.

### Step 1: Decode the JWT

Decode the JWT to extract the payload:

```swift
let jwtString = "your.jwt.string.here" // Replace with your JWT string
let jwt = try JWT.verify(jwtString: jwtString, signerKey: key)
```

### Step 2: Extract Custom Claims

Extract and decode the custom claims from the JWT payload:

```swift
let decoder = JSONDecoder.jwt
let customClaims = try decoder.decode(CustomClaims.self, from: jwt.payload)

print("User ID: \(customClaims.userId)")
print("Roles: \(customClaims.roles)")
print("Expiration: \(customClaims.exp)")
```
