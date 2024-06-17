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

final class JWSTests: XCTestCase {

    func testAutomaticHeaderAlgorithmES256() throws {
        let keyPair = JWK.testingES256Pair
        let testJWS = try JWS(payload: "test".data(using: .utf8)!, key: keyPair)
        XCTAssertEqual(testJWS.protectedHeader.algorithm, .ES256)
    }
    
    func testAutomaticHeaderAlgorithmES384() throws {
        let keyPair = JWK.testingES384Pair
        let testJWS = try JWS(payload: "test".data(using: .utf8)!, key: keyPair)
        XCTAssertEqual(testJWS.protectedHeader.algorithm, .ES384)
    }
    
    func testAutomaticHeaderAlgorithmES521() throws {
        let keyPair = JWK.testingES521Pair
        let testJWS = try JWS(payload: "test".data(using: .utf8)!, key: keyPair)
        XCTAssertEqual(testJWS.protectedHeader.algorithm, .ES512)
    }
    
    func testAutomaticHeaderAlgorithmES256K() throws {
        let keyPair = JWK.testingES256KPair
        let testJWS = try JWS(payload: "test".data(using: .utf8)!, key: keyPair)
        XCTAssertEqual(testJWS.protectedHeader.algorithm, .ES256K)
    }
    
    func testJWSTamperedPayload() throws {
            let originalJwsString = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        let tamperedPayload = Base64URL.encode("tamperedPayload".data(using: .ascii)!)
        let tamperedJwsString = "eyJhbGciOiJFUzUxMiJ9.\(tamperedPayload).AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        
        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let originalJWS = try JWS(jwsString: originalJwsString)
        let tamperedJWS = try JWS(jwsString: tamperedJwsString)
        
        XCTAssertTrue(try originalJWS.verify(key: jwk))
        XCTAssertFalse(try tamperedJWS.verify(key: jwk))
    }
    
    func testJWSTamperedHeader() throws {
            let originalJwsString = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        let tamperedHeader = Base64URL.encode("{\"tampered\":\"tampered\",\"alg\":\"ES512\"}".data(using: .utf8)!)
        let tamperedJwsString = "\(tamperedHeader).UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        
        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let originalJWS = try JWS(jwsString: originalJwsString)
        let tamperedJWS = try JWS(jwsString: tamperedJwsString)
        
        XCTAssertTrue(try originalJWS.verify(key: jwk))
        XCTAssertFalse(try tamperedJWS.verify(key: jwk))
    }
    
    func testJWSTamperedAlgorithm() throws {
            let originalJwsString = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        let tamperedHeader = Base64URL.encode("{\"tampered\":\"tampered\",\"alg\":\"ES256\"}".data(using: .utf8)!)
        let tamperedJwsString = "\(tamperedHeader).UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        
        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"alg\":\"ES512\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let originalJWS = try JWS(jwsString: originalJwsString)
        let tamperedJWS = try JWS(jwsString: tamperedJwsString)
        
        XCTAssertTrue(try originalJWS.verify(key: jwk))
        XCTAssertThrowsError(try tamperedJWS.verify(key: jwk))
    }
    
    func testES256SigningWithDataKey() throws {
        let keyPair = JWK.testingES256PairData
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: keyPair))
    }
    
    func testES256SigningWithSecKey() throws {
        let keyPair = JWK.testingES256PairSecKey
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256), key: keyPair))
    }
    
    func testES384SigningWithDataKey() throws {
        let keyPair = JWK.testingES384PairData
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES384), key: keyPair))
    }
    
    func testES512SigningWithDataKey() throws {
        let keyPair = JWK.testingES521Pair
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES512), key: keyPair))
    }
    
    func testES256KSigningWithDataKey() throws {
        let keyPair = JWK.testingES256KPairData
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256K), key: keyPair))
    }
    
    func testEdDSASigningWithDataKey() throws {
        let keyPair = JWK.testingCurve25519KPair
        XCTAssertNoThrow(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .EdDSA), key: keyPair))
    }
    
    func testWrongAlgKeySigningWithDataKey() throws {
        let keyPair = JWK.testingCurve25519KPair
        XCTAssertThrowsError(try JWS(payload: "test".data(using: .utf8)!, protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES512), key: keyPair))
    }
    
    func testJWSUnencodedPayloadCompactString() throws {
        let payload = "$.02"
        let keyPair = JWK.testingES256Pair
        let testJWS = try JWS(payload: payload.data(using: .utf8)!, key: keyPair, options: [.unencodedPayload])
        XCTAssertTrue(testJWS.compactSerialization.contains(".."))
        XCTAssertTrue(try JWS.verify(jwsString: testJWS.compactSerialization, payload: payload.data(using: .utf8)!, key: keyPair))
    }
}
