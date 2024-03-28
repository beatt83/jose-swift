import JSONWebKey
@testable import JSONWebToken
import JSONWebSignature
import XCTest

final class JWTTests: XCTestCase {

    func testParseSignedJWT() throws {
        let jwtString = """
        eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
        """
        
        let jwt = try JWT<DefaultJWTClaimsImpl>.verify(jwtString: jwtString)
        switch jwt.format {
        case .jws(let jws):
            XCTAssertEqual(jws.protectedHeader.algorithm!, .none)
            XCTAssertNil(jws.protectedHeader.type)
            XCTAssertNil(jws.protectedHeader.contentType)
        default:
            XCTFail("Wrong JWT format")
        }
        
        let expirationTime = jwt.payload.exp?.timeIntervalSince1970
        XCTAssertEqual(jwt.payload.iss, "joe")
        XCTAssertEqual(jwt.payload.exp!, Date(timeIntervalSince1970: 2279126580.0))
    }
    
    func testSignAndVerify() throws {
        let issuedAt = Date(timeIntervalSince1970: 0)
        let mockClaims = MockExampleClaims(
            iss: "testAlice",
            sub: "Alice",
            iat: issuedAt,
            testClaim: "testedClaim"
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString
        
        XCTAssertTrue(jwtString.contains("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"))
        XCTAssertTrue(jwtString.contains("eyJpYXQiOi05NzgzMDcyMDAsImlzcyI6InRlc3RBbGljZSIsInN1YiI6IkFsaWNlIiwidGVzdENsYWltIjoidGVzdGVkQ2xhaW0ifQ"))
        
        let verifiedJWT = try JWT<MockExampleClaims>.verify(jwtString: jwtString, senderKey: key)
        let verifiedPayload = verifiedJWT.payload
        XCTAssertEqual(verifiedPayload.iss, "testAlice")
        XCTAssertEqual(verifiedPayload.sub, "Alice")
        XCTAssertEqual(verifiedPayload.iat, issuedAt)
        XCTAssertEqual(verifiedPayload.testClaim, "testedClaim")
        switch verifiedJWT.format {
        case .jws(let jws):
            XCTAssertEqual(jws.protectedHeader.algorithm, .ES256)
        default:
            XCTFail()
        }
    }
    
    func testFailExpirationValidation() throws {
        let expiredAt = Date(timeIntervalSince1970: 0)
        let mockClaims = DefaultJWTClaimsImpl(
            iss: "testAlice",
            sub: "Alice",
            exp: expiredAt
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaimsImpl>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailNotBeforeValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaimsImpl(
            iss: "testAlice",
            sub: "Alice",
            nbf: nbf
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaimsImpl>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailIssuedAtValidation() throws {
        let issuedAt = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaimsImpl(
            iss: "testAlice",
            sub: "Alice",
            iat: issuedAt
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaimsImpl>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailIssuerValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaimsImpl(
            iss: "testAlice",
            sub: "Alice",
            nbf: nbf
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaimsImpl>.verify(
            jwtString: jwtString,
            senderKey: key,
            expectedIssuer: "Bob"
        ))
    }
    
    func testFailAudienceValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaimsImpl(
            iss: "testAlice",
            sub: "Alice",
            aud: ["Test"]
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaimsImpl>.verify(
            jwtString: jwtString,
            senderKey: key,
            expectedAudience: "Bob"
        ))
    }
}
