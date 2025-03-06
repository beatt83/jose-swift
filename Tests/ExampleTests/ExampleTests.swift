
import JSONWebKey
import JSONWebToken
import JSONWebSignature
import JSONWebEncryption
import CryptoKit
import CryptoSwift
import secp256k1
import XCTest

final class ExamplesTests: XCTestCase {

    func testExample1_1AndExample1_2() throws {
        // Generate a P256 private key
        let privateKey = P256.Signing.PrivateKey()

        // Create and sign the JWT
        let jwt = try JWT.signed(
            claims: {
                // Define the claims
                SubjectClaim(value: "1234567890")
                IssuedAtClaim(value: Date())
                StringClaim(key: "name", value: "John Doe")
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: privateKey
        )
        
        print(jwt.jwtString)
        
        // Extract the public key
        let publicKey = privateKey.publicKey

        // Verify the JWT
        let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: publicKey)
        
        print("Valid: \(isValid)")
    }
    
    func testExample1_3And1_4() throws {
        // Generate a P256 private key
        let privateKey = P256.Signing.PrivateKey()
        
        // Define the payload
        let payload = "Hello, JWS!".data(using: .utf8)!

        // Create and sign the JWS
        let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: privateKey)
        
        print(jws.compactSerialization)
        
        // Extract the public key
        let publicKey = privateKey.publicKey
        
        // Verify the JWS
        let isJWSValid = try jws.verify(key: publicKey)
        
        print("Valid: \(isJWSValid)")
    }
    
    func testExample1_5And1_6() throws {
        // Define the payload
        let payload = "Hello, JWE!".data(using: .utf8)!

        // Create and encrypt the JWE
        let recipientKey = P256.KeyAgreement.PrivateKey()
        let jwe = try JWE(payload: payload, keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM, recipientKey: recipientKey.publicKey)
        
        print(jwe.compactSerialization)
        
        let decryptedPayload = try jwe.decrypt(recipientKey: recipientKey)
        
        print("Encrypted payload: \(String(data: decryptedPayload, encoding: .utf8)!)")
    }
    
    func testExample1_7() throws {
        let payload = "Hello JSW!".data(using: .utf8)!
        // Generate a SecKey private key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let secPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("Failed to generate private key: \(error!.takeRetainedValue())")
        }

        // Sign a JWS using SecKey
        let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: secPrivateKey)

        //Verify the JWS using SecKey
        let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!
        let isJWSValid = try jws.verify(key: secPublicKey)
        
        print("Valid: \(isJWSValid)")
    }
    
    func testExample1_8() throws {
        let payload = "Hello JSW!".data(using: .utf8)!
        // Create a JWK
        let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))

        // Sign a JWS using JWK
        let jws = try JWS(payload: payload, protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256), key: jwk)

        // Verify the JWS using JWK
        let isJWSValid = try jws.verify(key: jwk)
        
        print("Valid: \(isJWSValid)")
    }
    
    func testExample2_1And2_2() throws {
        let key = P256.Signing.PrivateKey()
        let payload = "Hello, World!".data(using: .utf8)!

        let header = DefaultJWSHeaderImpl(algorithm: .ES256)
        let jws = try JWS(
            payload: payload,
            protectedHeader: header,
            key: key
        )

        print("JWS: \(jws.compactSerialization)")
        
        let jwsString = jws.compactSerialization
        let publicKey = key.publicKey
        let verificationJWS = try JWS(jwsString: jwsString)

        let isValid = try verificationJWS.verify(key: publicKey)
        print("Signature is valid: \(isValid)")
    }
    
    func testExample2_3() throws {
        let key = try secp256k1.Signing.PrivateKey()
        let payload = "Hello, World!".data(using: .utf8)!

        var header = DefaultJWSHeaderImpl(algorithm: .ES256K)
        header.keyID = "key-id"

        let jws = try JWS(
            payload: payload,
            protectedHeader: header,
            key: key
        )

        print("JWS: \(jws.compactSerialization)")
    }
    
    func testExample2_4() throws {
        let nestedKey = try RSA(keySize: 1228)
        let nestedPayload = "Nested payload".data(using: .utf8)!

        let nestedHeader = DefaultJWSHeaderImpl(algorithm: .RS512)
        let nestedJws = try JWS(
            payload: nestedPayload,
            protectedHeader: nestedHeader,
            key: nestedKey
        )

        let outerKey = P521.Signing.PrivateKey()
        let outerHeader = DefaultJWSHeaderImpl(algorithm: .ES512, contentType: "JWT")
        let outerJws = try JWS(
            payload: JSONEncoder().encode(nestedJws.compactSerialization),
            protectedHeader: outerHeader,
            key: outerKey
        )

        print("Nested JWS: \(outerJws.compactSerialization)")
    }
    
    func testExample3_1And3_2() throws {
        let payload = "Hello, World!".data(using: .utf8)!
        let recipientKey = try RSA(keySize: 2048)

        let jwe = try JWE(
            payload: payload,
            keyManagementAlg: .rsaOAEP,
            encryptionAlgorithm: .a256GCM,
            recipientKey: recipientKey
        )

        print("JWE: \(jwe.compactSerialization)")
        
        let jweString = jwe.compactSerialization
        let validateJWE = try JWE(compactString: jweString)

        let decryptedPayload = try validateJWE.decrypt(recipientKey: recipientKey)
        print("Decrypted payload: \(String(data: decryptedPayload, encoding: .utf8)!)")
    }
    
    func testExample3_3() throws {
        let payload = "Hello, World!".data(using: .utf8)!
        let recipientKey = try RSA(keySize: 2048)

        var header = DefaultJWEHeaderImpl(keyManagementAlgorithm: .rsaOAEP256, encodingAlgorithm: .a256GCM)
        header.keyID = "key-id"

        let jwe = try JWE(
            payload: payload,
            protectedHeader: header,
            recipientKey: recipientKey
        )

        print("JWE: \(jwe.compactSerialization)")
    }
    
    func testExample3_4() throws {
        let nestedPayload = "Nested payload".data(using: .utf8)!
        let nestedRecipientKey = try RSA(keySize: 2048)

        let nestedJwe = try JWE(
            payload: nestedPayload,
            keyManagementAlg: .rsaOAEP,
            encryptionAlgorithm: .a256GCM,
            recipientKey: nestedRecipientKey
        )

        let outerRecipientKey = try RSA(keySize: 2048)
        let outerJwe = try JWE(
            payload: JSONEncoder().encode(nestedJwe.compactSerialization),
            keyManagementAlg: .rsaOAEP,
            encryptionAlgorithm: .a256GCM,
            recipientKey: outerRecipientKey
        )

        print("Nested JWE: \(outerJwe.compactSerialization)")
    }
    
    func testExample4_1And4_2() throws {
        let key = P256.Signing.PrivateKey()
        let jwt = try JWT.signed(
            claims: {
                IssuerClaim(value: "your-issuer")
                SubjectClaim(value: "your-subject")
                ExpirationTimeClaim(value: Date().addingTimeInterval(3600)) // 1 hour expiration
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key.jwkRepresentation
        )

        print("JWT: \(jwt.jwtString)")
        
        let jwtString = jwt.jwtString
        let verifiedJWT = try JWT.verify(jwtString: jwtString, signerKey: key)

        print("Verified JWT Payload: \(verifiedJWT.payload)")
    }
    
    func testExample4_3() throws {
        struct DemoError: Error {}
        struct CustomClaims: JWTRegisteredFieldsClaims, Codable {
            let iss: String?
            let sub: String?
            let aud: [String]?
            let exp: Date?
            let nbf: Date?
            let iat: Date?
            let jti: String?
            let customClaim: String
            
            init(
                iss: String? = nil,
                sub: String? = nil,
                aud: [String]? = nil,
                exp: Date? = nil,
                nbf: Date? = nil,
                iat: Date? = nil,
                jti: String? = nil,
                customClaim: String
            ) {
                self.iss = iss
                self.sub = sub
                self.aud = aud
                self.exp = exp
                self.nbf = nbf
                self.iat = iat
                self.jti = jti
                self.customClaim = customClaim
            }
            
            func validateExtraClaims() throws {
                // Any extra validation
                guard customClaim == "custom-value" else {
                    throw DemoError()
                }
            }
        }

        let key = P256.Signing.PrivateKey()
        let claims = CustomClaims(iss: "your-issuer", sub: "your-subject", customClaim: "custom-value")

        let jwt = try JWT.signed(
            payload: claims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
    }
    
    func testExample4_4() throws {
        let key = P256.Signing.PrivateKey()
        let jwt = try JWT.signed(
            claims: {
                IssuerClaim(value: "your-issuer")
                SubjectClaim(value: "your-subject")
                ExpirationTimeClaim(value: Date().addingTimeInterval(3600)) // 1 hour expiration
                ObjectClaim(key: "address") {
                    StringClaim(key: "street", value: "Rua Sesamo")
                    NumberClaim(key: "buildingNumber", value: 1)
                    BoolClaim(key: "isBuilding", value: true)
                }
                ArrayClaim(key: "nickNames") {
                    ArrayElementClaim.string("Me")
                    ArrayElementClaim.string("Myself")
                    ArrayElementClaim.string("I")
                }
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key.jwkRepresentation
        )
    }
    
    func testExample5_1() throws {
        struct MyClaims: JWTRegisteredFieldsClaims, Codable {
            var iss: String?
            var aud: [String]?
            var exp: Date?
            var nbf: Date?
            var iat: Date?
            var jti: String?
            let sub: String?
            let name: String
            
            init(
                iss: String? = nil,
                aud: [String]? = nil,
                exp: Date? = nil,
                nbf: Date? = nil,
                iat: Date? = nil,
                jti: String? = nil,
                sub: String? = nil,
                name: String
            ) {
                self.iss = iss
                self.aud = aud
                self.exp = exp
                self.nbf = nbf
                self.iat = iat
                self.jti = jti
                self.sub = sub
                self.name = name
            }
            
            func validateExtraClaims() throws {}
        }

        let _ = MyClaims(iat: Date(), sub: "1234567890", name: "John Doe")
    }
    
    func testExample5_2And5_3And5_4And5_5() throws {
        // Generate a P256 private key
        let privateKey = P256.Signing.PrivateKey()

        // Create and sign the JWT
        let jwt = try JWT.signed(
            claims: {
                // Define the claims
                SubjectClaim(value: "1234567890")
                IssuedAtClaim(value: Date())
                StringClaim(key: "name", value: "John Doe")
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: privateKey
        )
        
        // Print the JWT string
        print(jwt.jwtString)

        // Print the JWT payload
        print(jwt.payload)
        
        // Extract the public key
        let publicKey = privateKey.publicKey

        // Verify the JWT
        let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: publicKey)
        print("JWT is valid: \(isValid)")
    }
    
    func testExample5_6() throws {
        // Generate a SecKey private key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let secPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("Failed to generate private key: \(error!.takeRetainedValue())")
        }

        // Sign a JWT using SecKey
        let jwt = try JWT.signed(
            claims: {
                IssuerClaim(value: "some-issuer")
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: secPrivateKey
        )

        // Verify the JWT using SecKey
        let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!
        let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: secPublicKey)
        print("JWT is valid: \(isValid)")
    }
    
    func testExample5_7() throws {
        // Create a JWK
        let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))

        // Sign a JWT using JWK
        let jwt = try JWT.signed(
            claims: {
                IssuerClaim(value: "some-issuer")
            },
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
            key: jwk
        )

        // Verify the JWT using JWK
        let isValid = try JWT.verify(jwtString: jwt.jwtString, senderKey: jwk)
        print("JWT is valid: \(isValid)")
    }
    
    // This is not supposed to run but exist to verify the code sintax is correct of the example
    func example6_1() throws {
        // Extract the public key from the private key
        // Replace with the pair public key
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: Data())

        // JWT string to verify
        let jwtString = "your.jwt.string"

        // Verify the JWT works for both Signed and Encoded JWTs, it will automatically identify
        // the correct algorithm and type of JWT
        // Signed JWT
        let signedJWT = try JWT.verify(jwtString: jwtString, senderKey: publicKey)
        // Encoded JWT
        let encodedJWT = try JWT.verify(jwtString: jwtString, senderKey: publicKey)
        print("No errors so your JWT is verified: \(signedJWT.jwtString)")
    }
    
    func example6_2() throws {
        // Generate a SecKey private key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let secPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("Failed to generate private key: \(error!.takeRetainedValue())")
        }

        // Extract the public key from the SecKey private key
        let secPublicKey = SecKeyCopyPublicKey(secPrivateKey)!

        // JWT string to verify
        let jwtString = "your.jwt.string"

        // Verify the JWT
        let jwt = try JWT.verify(jwtString: jwtString, senderKey: secPublicKey)
        print("No errors so your JWT is verified: \(jwt.jwtString)")
    }
    
    func example6_3() throws {
        // Create a JWK
        let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))

        // JWT string to verify
        let jwtString = "your.jwt.string"

        // Verify the JWT
        let jwt = try JWT.verify(jwtString: jwtString, senderKey: jwk)
        print("No errors so your JWT is verified: \(jwt.jwtString)")
    }
    
    func example6_4() throws {
        // Define the expected issuer and audience
        let expectedIssuer = "your-issuer"
        let expectedAudience = "your-audience"

        let jwk = JWK(keyType: .octetSequence, key: Data(repeating: 0, count: 32))
        // The library verifies automatically iat, nbf and exp but you can pass values for iss, sub and aud
        let jwt = try JWT.verify(jwtString: "your.jwt.here", senderKey: jwk, expectedIssuer: expectedIssuer, expectedAudience: expectedAudience)
        print("No errors so your JWT is verified: \(jwt.jwtString)")
    }
    
    func testExample7_1() throws {
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
            cek: cek
        )

        // Output the encrypted JWT string:
        print(encryptedJWT.jwtString)
    }
    
    func testExample7_2() throws {
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
            recipientKey: publicKey
        )

        // Output the encrypted JWT string:
        print(encryptedJWT.jwtString)
    }
    
    func examples8() throws {
        struct CustomClaims: Codable, JWTRegisteredFieldsClaims {
            let iss: String?
            let sub: String?
            let aud: [String]?
            let exp: Date?
            let nbf: Date?
            let iat: Date?
            let jti: String?
            let userId: String
            let roles: [String]
            
            init(
                iss: String? = nil,
                sub: String? = nil,
                aud: [String]? = nil,
                exp: Date? = nil,
                nbf: Date? = nil,
                iat: Date? = nil,
                jti: String? = nil,
                userId: String,
                roles: [String]
            ) {
                self.iss = iss
                self.sub = sub
                self.aud = aud
                self.exp = exp
                self.nbf = nbf
                self.iat = iat
                self.jti = jti
                self.userId = userId
                self.roles = roles
            }
            
            func validateExtraClaims() throws {}
        }
        
        let customClaims = CustomClaims(
            exp: Date().addingTimeInterval(3600), // 1 hour expiration
            userId: "12345",
            roles: ["admin", "user"]
        )
        
        let protectedHeader = DefaultJWSHeaderImpl(algorithm: .HS256)
        let key = SymmetricKey(size: .bits256) // Replace with your key

        let jwt = try JWT.signed(
            payload: customClaims,
            protectedHeader: protectedHeader,
            key: key
        )

        print("Signed JWT: \(jwt.jwtString)")
        
        let jwtString = "your.jwt.string.here" // Replace with your JWT string
        let verifiedJWT = try JWT.verify(jwtString: jwtString, signerKey: key)
        
        let decoder = JSONDecoder.jwt
        let decodedCustomClaims = try decoder.decode(CustomClaims.self, from: jwt.payload)

        print("User ID: \(customClaims.userId)")
        print("Roles: \(customClaims.roles)")
        print("Expiration: \(decodedCustomClaims.exp!)")
    }
    
    func testExample9_1() throws {
        let innerJWTHeader = DefaultJWSHeaderImpl(algorithm: .ES256)
        
        let p256SigningKey = P256.Signing.PrivateKey()
        let jwt = try JWT.signed(
            claims: {
                IssuerClaim(value: "some-issuer")
            },
            protectedHeader: innerJWTHeader,
            key: p256SigningKey
        )
        
        let p256EncodingKey = P384.KeyAgreement.PrivateKey()
        
        let outerJWTHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: .ecdhESA256KW,
            encodingAlgorithm: .a256GCM
        )
        
        let nestedJWT = try JWT.encryptAsNested(jwt: jwt, protectedHeader: outerJWTHeader, recipientKey: p256EncodingKey)
        print(nestedJWT.jwtString)
        
        let verifiedJWT = try JWT.verify(jwtString: nestedJWT.jwtString, recipientKey: p256EncodingKey, nestedKeys: [p256SigningKey])
        print(try verifiedJWT.payload.tryToString())
    }
    
    func exampleReadme1() throws {
        let payload = "Hello world".data(using: .utf8)!
        let key = try secp256k1.Signing.PrivateKey()

        let jws = try JWS(payload: payload, key: key)

        let jwsString = jws.compactSerialization

        _ = try JWS(jwsString: jwsString).verify(key: key)
    }
    
    func exampleReadme2() throws {
        let payload = "Hello world".data(using: .utf8)!
        let key = try secp256k1.Signing.PrivateKey()

        let jws = try JWS(payload: payload, key: key, options: [.unencodedPayload])

        let jwsString = jws.compactSerialization

        _ = try JWS.verify(jwsString: jwsString, payload: payload, key: key)
    }
}
