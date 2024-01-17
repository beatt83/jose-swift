/*
 * Copyright 2024 Gonçalo Frade
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import JSONWebKey
@testable import JSONWebSignature
import Tools
import XCTest

final class JWSJsonTests: XCTestCase {

    func testJsonSerializationOneKeyOnlyES256() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerialization(payload: payload.data(using: .utf8)!, keys: [jwk])
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        XCTAssertEqual(jsonSerilization.signatures.count, 1)
        XCTAssertEqual(try jsonSerilization.signatures.first!.validateAlg(), .ES256)
        XCTAssertEqual(try jsonSerilization.signatures.first!.getKid(), "1")
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: jwk))
    }
    
    func testJsonSerializationTwoKeysES256() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        
        let keyJWK2 = "{\"kty\":\"EC\",\"kid\":\"2\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        
        let jwk1 = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        let jwk2 = try JSONDecoder().decode(JWK.self, from: keyJWK2.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerialization(payload: payload.data(using: .utf8)!, keys: [jwk1, jwk2])
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        XCTAssertEqual(jsonSerilization.signatures.count, 2)
        XCTAssertEqual(try jsonSerilization.signatures.filter { try $0.validateAlg() == .ES256 }.count, 2)
        XCTAssertTrue(try jsonSerilization.signatures.contains { try $0.getKid() == "1"} )
        XCTAssertTrue(try jsonSerilization.signatures.contains { try $0.getKid() == "2"} )
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: jwk1))
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: jwk2))
    }
    
    func testJsonSerializationOneKeyES256_OtherES521() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        
        let keyJWK2 = "{\"kty\":\"EC\",\"kid\":\"2\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        
        let jwk1 = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        let jwk2 = try JSONDecoder().decode(JWK.self, from: keyJWK2.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerialization(payload: payload.data(using: .utf8)!, keys: [jwk1, jwk2])
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        XCTAssertEqual(jsonSerilization.signatures.count, 2)
        XCTAssertEqual(try jsonSerilization.signatures.filter { try $0.validateAlg() == .ES256 }.count, 1)
        XCTAssertEqual(try jsonSerilization.signatures.filter { try $0.validateAlg() == .ES512 }.count, 1)
        XCTAssertTrue(try jsonSerilization.signatures.contains { try $0.getKid() == "1"} )
        XCTAssertTrue(try jsonSerilization.signatures.contains { try $0.getKid() == "2"} )
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: jwk1))
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: jwk2))
    }
    
    func testJsonSerializationTrueES256Verification_FailES521VerificationWithRandomKey() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk1 = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let jws = """
{"payload":"eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==","signatures":[{"header":{"kid":"1"},"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"vlYj-Vt5onyW56JMnWA82dlylnf2ELGfrGXP7P_JVUY3Dftecm83ceW9w6FYF4ApacRym6Mu5n_NtWDPgK35yg"},{"header":{"kid":"2"},"protected":"eyJhbGciOiJFUzUxMiJ9","signature":"AST-iRjis7O62AjCJBdOk-n54P73JZ_hCJZHBMTcqbrBD7Nhd0PysbDGZQf1IsD2LHcAvL_H2LR-p-QsmDViooHQAI9LaK8abwQYIDrYNc9fGSaVdWw42qzqj_m9qGhM5jLEcGW-PrNYUGsJSsBC4daBXnxEUbCR7iR0UVaR00ngb4Ma"}]}
"""
        
        let jwkRandomKey = JWK.testingES521Pair
        
        XCTAssertTrue(try JWS.verify(jwsJson: jws.data(using: .utf8)!, jwk: jwk1))
        XCTAssertFalse(try JWS.verify(jwsJson: jws.data(using: .utf8)!, jwk: jwkRandomKey, validateAll: true))
    }
    
    func testJsonSerializationVerificationTrueWhenKeyIsValidWithoutKidAndValidateAllTrue() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk1 = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let keyJWKWithoutKid = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwkWithoutKid = try JSONDecoder().decode(JWK.self, from: keyJWKWithoutKid.data(using: .utf8)!)
        
        let jws = """
{"payload":"eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==","signatures":[{"header":{"kid":"1"},"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"vlYj-Vt5onyW56JMnWA82dlylnf2ELGfrGXP7P_JVUY3Dftecm83ceW9w6FYF4ApacRym6Mu5n_NtWDPgK35yg"},{"header":{"kid":"2"},"protected":"eyJhbGciOiJFUzUxMiJ9","signature":"AST-iRjis7O62AjCJBdOk-n54P73JZ_hCJZHBMTcqbrBD7Nhd0PysbDGZQf1IsD2LHcAvL_H2LR-p-QsmDViooHQAI9LaK8abwQYIDrYNc9fGSaVdWw42qzqj_m9qGhM5jLEcGW-PrNYUGsJSsBC4daBXnxEUbCR7iR0UVaR00ngb4Ma"}]}
"""
        
        XCTAssertTrue(try JWS.verify(jwsJson: jws.data(using: .utf8)!, jwk: jwkWithoutKid, validateAll: true))
    }
    
    func testJsonSerializationVerificationFalseWhenKeyHasNoKid() throws {
        let keyJWK = "{\"kty\":\"EC\",\"kid\":\"1\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk1 = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let keyJWKWithoutKid = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwkWithoutKid = try JSONDecoder().decode(JWK.self, from: keyJWKWithoutKid.data(using: .utf8)!)
        
        let jws = """
{"payload":"eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==","signatures":[{"header":{"kid":"1"},"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"vlYj-Vt5onyW56JMnWA82dlylnf2ELGfrGXP7P_JVUY3Dftecm83ceW9w6FYF4ApacRym6Mu5n_NtWDPgK35yg"},{"header":{"kid":"2"},"protected":"eyJhbGciOiJFUzUxMiJ9","signature":"AST-iRjis7O62AjCJBdOk-n54P73JZ_hCJZHBMTcqbrBD7Nhd0PysbDGZQf1IsD2LHcAvL_H2LR-p-QsmDViooHQAI9LaK8abwQYIDrYNc9fGSaVdWw42qzqj_m9qGhM5jLEcGW-PrNYUGsJSsBC4daBXnxEUbCR7iR0UVaR00ngb4Ma"}]}
"""
        
        XCTAssertThrowsError(try JWS.verify(jwsJson: jws.data(using: .utf8)!, jwk: jwkWithoutKid))
    }
    
    func testJsonSerializationOneKeyOnlyEdDSA() throws {
        var keyJWK = JWK.testingCurve25519KPair
        keyJWK.keyID = "1"
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerialization(payload: payload.data(using: .utf8)!, keys: [keyJWK])
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        XCTAssertEqual(jsonSerilization.signatures.count, 1)
        XCTAssertEqual(try jsonSerilization.signatures.first!.validateAlg(), .EdDSA)
        XCTAssertEqual(try jsonSerilization.signatures.first!.getKid(), "1")
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: keyJWK))
    }
}
