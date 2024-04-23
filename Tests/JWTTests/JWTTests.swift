import JSONWebKey
@testable import JSONWebToken
import JSONWebSignature
import XCTest

final class JWTTests: XCTestCase {

    func testParseSignedJWT() throws {
        let jwtString = """
        eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0QWxpY2UiLCJzdWIiOiJBbGljZSIsInRlc3RDbGFpbSI6InRlc3RlZENsYWltIn0.
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
        
        XCTAssertEqual(jwt.payload.iss, "testAlice")
    }
    
    func testSignAndVerify() throws {
        let issuedAt = Date(timeIntervalSince1970: 200)
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
        XCTAssertTrue(jwtString.contains("eyJpYXQiOjIwMCwiaXNzIjoidGVzdEFsaWNlIiwic3ViIjoiQWxpY2UiLCJ0ZXN0Q2xhaW0iOiJ0ZXN0ZWRDbGFpbSJ9"))
        
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
