import JSONWebKey
@testable import JSONWebToken
import JSONWebSignature
import JSONWebEncryption
import XCTest

final class JWTTests: XCTestCase {

    func testParseSignedJWT() throws {
        let jwtString = """
        eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0QWxpY2UiLCJzdWIiOiJBbGljZSIsInRlc3RDbGFpbSI6InRlc3RlZENsYWltIn0.
        """
        
        let jwt = try JWT.verify(jwtString: jwtString)
        switch jwt.format {
        case .jws(let jws):
            XCTAssertEqual(jws.protectedHeader.algorithm!, .none)
            XCTAssertNil(jws.protectedHeader.type)
            XCTAssertNil(jws.protectedHeader.contentType)
        default:
            XCTFail("Wrong JWT format")
        }
        
        XCTAssertEqual(try JSONDecoder.jwt.decode(DefaultJWTClaimsImpl.self, from: jwt.payload).iss, "testAlice")
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
        
        let verifiedJWT = try JWT.verify(jwtString: jwtString, senderKey: key)
        let verifiedPayload = try JSONDecoder.jwt.decode(MockExampleClaims.self, from: verifiedJWT.payload)
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

        XCTAssertThrowsError(try JWT.verify(jwtString: jwtString, senderKey: key))
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

        XCTAssertThrowsError(try JWT.verify(jwtString: jwtString, senderKey: key))
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

        XCTAssertThrowsError(try JWT.verify(jwtString: jwtString, senderKey: key))
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

        XCTAssertThrowsError(try JWT.verify(
            jwtString: jwtString,
            senderKey: key,
            validators: [.iss(expectedIssuer: "Bob", required: false)]
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

        XCTAssertThrowsError(try JWT.verify(
            jwtString: jwtString,
            senderKey: key,
            validators: [.aud(expectedAudience: ["Bob"], required: false)]
        ))
    }
    
    @JWTClaimsBuilder var resultTestClaims: ObjectClaim {
        IssuerClaim(value: "testIssuer")
        SubjectClaim(value: "testSubject")
        ExpirationTimeClaim(value: Date(timeIntervalSince1970: 1609459200)) // Fixed date for testing
        IssuedAtClaim(value: Date(timeIntervalSince1970: 1609459200))
        NotBeforeClaim(value: Date(timeIntervalSince1970: 1609459200))
        JWTIdentifierClaim(value: "ThisIdentifier")
        AudienceClaim(value: "testAud")
        StringClaim(key: "testStr1", value: "value1")
        NumberClaim(key: "testN1", value: 0)
        NumberClaim(key: "testN2", value: 1.1)
        NumberClaim(key: "testN3", value: Double(1.233232))
        BoolClaim(key: "testBool1", value: true)

        if true {
            StringClaim(key: "willShow", value: "testValue")
            StringClaim(key: "willShow2", value: "testValue")
        } else {
            StringClaim(key: "dontShow", value: "testValue")
        }
        ArrayClaim(key: "testArray") {
            ArrayElementClaim.string("valueArray1")
            ArrayElementClaim.string("valueArray2")
            ArrayElementClaim.bool(true)
            ArrayElementClaim.array {
                ArrayElementClaim.string("nestedNestedArray1")
            }
            ArrayElementClaim.object {
                StringClaim(key: "nestedNestedObject", value: "nestedNestedValue")
            }
        }
        ObjectClaim(key: "testObject") {
            StringClaim(key: "testDicStr1", value: "valueDic1")
        }
    }
    
    func testClaims() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .secondsSince1970
        let coded = try encoder.encode(resultTestClaims.value)
        
        let jsonString = try XCTUnwrap(String(data: coded, encoding: .utf8))
        // Verify the structure of the resulting JSON
        let expectedJSON = """
        {
            "aud":"testAud",
            "exp":1609459200,
            "iat":1609459200,
            "iss":"testIssuer",
            "jti":"ThisIdentifier",
            "nbf":1609459200,
            "sub":"testSubject",
            "testArray":[
                "valueArray1",
                "valueArray2",
                true,
                ["nestedNestedArray1"],
                {"nestedNestedObject":"nestedNestedValue"}
            ],
            "testBool1":true,
            "testN1":0,
            "testN2":1.1,
            "testN3":1.233232,
            "testObject":{"testDicStr1":"valueDic1"},
            "testStr1":"value1",
            "willShow":"testValue",
            "willShow2":"testValue"
        }
        """.replacingWhiteSpacesAndNewLines()
        XCTAssertFalse(jsonString.contains("dontShow"))
        XCTAssertEqual(jsonString, expectedJSON)
    }
    
    func testJWTClaims() throws {
        try JWT.signed(
            claims: {
            },
            protectedHeader: DefaultJWSHeaderImpl(keyID: ""),
            key: nil as JWK?
        )
    }
    
    @JWTClaimsBuilder var resultTestSingleClaim: ObjectClaim {
        IssuerClaim(value: "singleIssuer")
    }
    
    func testSingleClaim() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .secondsSince1970
        let coded = try encoder.encode(resultTestSingleClaim.value)
        
        let jsonString = try XCTUnwrap(String(data: coded, encoding: .utf8))
        print(jsonString)
        
        // Verify the structure of the resulting JSON
        let expectedJSON = """
        {
            "iss":"singleIssuer"
        }
        """
        
        XCTAssertTrue(areJSONStringsEqual(jsonString, expectedJSON))
    }
    
    private func areJSONStringsEqual(_ lhs: String, _ rhs: String) -> Bool {
        guard
            let lhsData = lhs.data(using: .utf8),
            let rhsData = rhs.data(using: .utf8),
            let lhsObject = try? JSONSerialization.jsonObject(with: lhsData, options: []),
            let rhsObject = try? JSONSerialization.jsonObject(with: rhsData, options: [])
        else {
            return false
        }
        return NSDictionary(dictionary: lhsObject as? [String: Any] ?? [:])
            .isEqual(to: rhsObject as? [String: Any] ?? [:])
    }
}

func build(@JWTClaimsBuilder builder: () throws -> [Claim]) rethrows -> ObjectClaim {
    JWTClaimsBuilder.buildFinalResult(try builder())
}

extension String {
    /// Returns a new string with all whitespace and newline characters removed.
    ///
    /// This method creates a new string with all occurrences of whitespace and newline characters (spaces and line breaks) removed. The original string is not modified.
    ///
    /// - Returns: A new string with all whitespace and newline characters removed.
    func replacingWhiteSpacesAndNewLines() -> String {
        replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
    }
}
