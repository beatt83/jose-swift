import JSONWebKey
@testable import JSONWebToken
import JSONWebSignature
import XCTest

final class JWTTests: XCTestCase {

    func testParseSignedJWT() throws {
        let jwtString = """
        eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
        """
        
        let jwt = try JWT<DefaultJWTClaims>.verify(jwtString: jwtString)
        switch jwt.format {
        case .jws(let jws):
            XCTAssertEqual(jws.protectedHeader.algorithm!, .none)
            XCTAssertNil(jws.protectedHeader.type)
            XCTAssertNil(jws.protectedHeader.contentType)
        default:
            XCTFail("Wrong JWT format")
        }
        
        let expirationTime = jwt.payload.expirationTime?.timeIntervalSince1970
        XCTAssertEqual(jwt.payload.issuer, "joe")
        XCTAssertEqual(jwt.payload.expirationTime!, Date(timeIntervalSince1970: 2279126580.0))
    }
    
    func testSignAndVerify() throws {
        let issuedAt = Date(timeIntervalSince1970: 0)
        let mockClaims = MockExampleClaims(
            issuer: "testAlice",
            subject: "Alice",
            issuedAt: issuedAt,
            testClaim: "testedClaim"
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertTrue(jwtString.contains("eyJhbGciOiJFUzI1NiJ9"))
        XCTAssertTrue(jwtString.contains("eyJpc3N1ZWRBdCI6LTk3ODMwNzIwMCwiaXNzdWVyIjoidGVzdEFsaWNlIiwic3ViamVjdCI6IkFsaWNlIiwidGVzdENsYWltIjoidGVzdGVkQ2xhaW0ifQ"))
        
        let verifiedJWT = try JWT<MockExampleClaims>.verify(jwtString: jwtString, senderKey: key)
        let verifiedPayload = verifiedJWT.payload
        XCTAssertEqual(verifiedPayload.issuer, "testAlice")
        XCTAssertEqual(verifiedPayload.subject, "Alice")
        XCTAssertEqual(verifiedPayload.issuedAt, issuedAt)
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
        let mockClaims = DefaultJWTClaims(
            issuer: "testAlice",
            subject: "Alice",
            expirationTime: expiredAt
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaims>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailNotBeforeValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaims(
            issuer: "testAlice",
            subject: "Alice",
            notBeforeTime: nbf
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaims>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailIssuedAtValidation() throws {
        let issuedAt = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaims(
            issuer: "testAlice",
            subject: "Alice",
            issuedAt: issuedAt
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaims>.verify(jwtString: jwtString, senderKey: key))
    }
    
    func testFailIssuerValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaims(
            issuer: "testAlice",
            subject: "Alice",
            notBeforeTime: nbf
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaims>.verify(
            jwtString: jwtString,
            senderKey: key,
            expectedIssuer: "Bob"
        ))
    }
    
    func testFailAudienceValidation() throws {
        let nbf = Date(timeIntervalSinceNow: 1000)
        let mockClaims = DefaultJWTClaims(
            issuer: "testAlice",
            subject: "Alice",
            audience: ["Test"]
        )
        
        let key = JWK.testingES256Pair
        
        let jwt = try JWT.signed(
            payload: mockClaims,
            protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
            key: key
        )
        
        let jwtString = jwt.jwtString

        XCTAssertThrowsError(try JWT<DefaultJWTClaims>.verify(
            jwtString: jwtString,
            senderKey: key,
            expectedAudience: "Bob"
        ))
    }
}
