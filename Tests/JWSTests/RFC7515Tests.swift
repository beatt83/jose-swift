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

import JSONWebAlgorithms
import JSONWebKey
@testable import JSONWebSignature
import Tools
import XCTest

final class RFC7515Tests: XCTestCase {
    
    func disabled_testJWS_RFC7515_A1_1() throws {
        // TODO: Re-enable test when flaky behaviour is discovered
        // Warning: This test is unreliable, so it disabled, it needs to be investigated why sometimes it fails and others passes, the problem seems to be on Apple HMAC<SHA256>
        // Input JWS String from RFC 7515 A.1.1
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
        let keyJWK = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws = try JWS(
            header: DefaultJWSHeaderImpl(algorithm: .HS256, type: "JWT"),
            data: payload.data(using: .utf8)!,
            key: jwk
        )
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .HS256)
        XCTAssertEqual(jws.protectedHeader.type, "JWT")
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8))
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A1_2() throws {
        // Input JWS String from RFC 7515 A.1.2
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.2
        let inputJwsString = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        

        let keyJWK = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws = try JWS(jwsString: inputJwsString)
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .HS256)
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8))
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A2_1() throws {
        // Input JWS String from RFC 7515 A.2.1
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2.1
        let keyJWK = JWK(
            keyType: .rsa,
            algorithm: SigningAlgorithm.RS256.rawValue,
            e: try Base64URL.decode("AQAB"),
            p: try Base64URL.decode("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
            q: try Base64URL.decode("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
            n: try Base64URL.decode("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
            dp: try Base64URL.decode("BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"),
            dq: try Base64URL.decode("h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"),
            qi: try Base64URL.decode("IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"),
            d: try Base64URL.decode("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ")
        )
        
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws = try JWS(
            header: DefaultJWSHeaderImpl(algorithm: .RS256),
            data: payload.data(using: .utf8)!,
            key: keyJWK
        )
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .RS256)
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8))
        
        XCTAssertTrue(try jws.verify(key: keyJWK))
    }
    
    func testJWS_RFC7515_A2_1_1() throws {
        // Input JWS String from RFC 7515 A.2.2
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2.2
        let inputJWSString = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

        let keyJWK = JWK(
            keyType: .rsa,
            e: try Base64URL.decode("AQAB"),
            p: try Base64URL.decode("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
            q: try Base64URL.decode("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
            n: try Base64URL.decode("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
            dp: try Base64URL.decode("BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"),
            dq: try Base64URL.decode("h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"),
            qi: try Base64URL.decode("IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"),
            d: try Base64URL.decode("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ")
        )
        
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws = try JWS(jwsString: inputJWSString)
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .RS256)
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8))
        
        XCTAssertTrue(try jws.verify(key: keyJWK))
    }
    
    func testJWS_RFC7515_A3_1() throws {
        // Input JWS String from RFC 7515 A.3.1
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.1

        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
        
        let jws = try JWS(data: payload.data(using: .utf8)!, key: jwk)
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .ES256)
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8))
        
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A3_1_1() throws {
        // Input JWS String from RFC 7515 A.3.2
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3.2
        let inputJWS = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        
        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws = try JWS(jwsString: inputJWS)
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .ES256)
        XCTAssertEqual(payload, String(data: jws.data, encoding: .utf8)!)
        
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A4_1() throws {
        // Input JWS String from RFC 7515 A.4.1
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4.1

        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "Payload"
        
        let jws = try JWS(
            header: DefaultJWSHeaderImpl(algorithm: .ES512),
            data: payload.data(using: .utf8)!,
            key: jwk
        )
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .ES512)
        XCTAssertEqual(payload.data(using: .ascii)!, jws.data)
        
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A4_1_1() throws {
        // Input JWS String from RFC 7515 A.4.2
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.4.2
        let inputJWS = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
        
        let keyJWK = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
        let jwk = try JSONDecoder().decode(JWK.self, from: keyJWK.data(using: .utf8)!)
        
        let payload = "Payload"
        
        let jws = try JWS(jwsString: inputJWS)
        
        XCTAssertEqual(jws.protectedHeader.algorithm, .ES512)
        XCTAssertEqual(payload.data(using: .ascii)!, jws.data)
        
        XCTAssertTrue(try jws.verify(key: jwk))
    }
    
    func testJWS_RFC7515_A5() throws {
        // Input JWS String from RFC 7515 A.5
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.5
        let inputJWS = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws = try JWS(jwsString: inputJWS)
        
        XCTAssertEqual(.none ,jws.protectedHeader.algorithm!)
        XCTAssertEqual(payload.data(using: .utf8)!, jws.data)
    }
    
    func testJWS_RFC7515_A6() throws {
        // Input JWS String from RFC 7515 A.6
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.6
        let rsa256KeyJWK = JWK(
            keyType: .rsa,
            algorithm: SigningAlgorithm.RS256.rawValue,
            keyID: "2010-12-29",
            e: try Base64URL.decode("AQAB"),
            p: try Base64URL.decode("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
            q: try Base64URL.decode("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
            n: try Base64URL.decode("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
            dp: try Base64URL.decode("BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"),
            dq: try Base64URL.decode("h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"),
            qi: try Base64URL.decode("IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"),
            d: try Base64URL.decode("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ")
        )
        
        let es256KeyJWKString = "{\"kty\":\"EC\",\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        
        let es256KeyJWK = try JSONDecoder().decode(JWK.self, from: es256KeyJWKString.data(using: .utf8)!)
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerialization(
            payload: payload.data(using: .utf8)!,
            keys: [rsa256KeyJWK, es256KeyJWK]
        )
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        let rsaSignature = try jsonSerilization.signatures.first { try $0.validateAlg() == .RS256 }
        let esSignature = try jsonSerilization.signatures.first { try $0.validateAlg() == .ES256 }
        
        XCTAssertNotNil(rsaSignature)
        XCTAssertNotNil(esSignature)
        XCTAssertEqual(Base64URL.encode(rsaSignature!.protectedData!), "eyJhbGciOiJSUzI1NiJ9")
        XCTAssertEqual(rsaSignature!.header!.keyID, "2010-12-29")
        XCTAssertEqual(Base64URL.encode(rsaSignature!.signature), "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw")
        XCTAssertEqual(Base64URL.encode(esSignature!.protectedData!), "eyJhbGciOiJFUzI1NiJ9")
        XCTAssertEqual(esSignature!.header!.keyID, "e9bc097a-ce51-4036-9562-d2ade882db0d")
        // We cannot test if the ES256 signature is equal since the value is always different,
        // instead we verify with the key
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: es256KeyJWK))
    }
    
    func testJWS_RFC7515_A7() throws {
        // Input JWS String from RFC 7515 A.7
        // Related documentation: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.7
        let es256KeyJWKString = "{\"kty\":\"EC\",\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
        
        let es256KeyJWK = try JSONDecoder().decode(JWK.self, from: es256KeyJWKString.data(using: .utf8)!)
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        
        let jws: Data = try JWS.jsonSerializationFlattened(
            payload: payload.data(using: .utf8)!,
            key: es256KeyJWK
        )
        
        let jsonSerilization = try JSONDecoder()
            .decode(JWSJsonFlattened<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.self, from: jws)
        
        XCTAssertEqual(Base64URL.encode(jsonSerilization.protectedData!), "eyJhbGciOiJFUzI1NiJ9")
        XCTAssertEqual(jsonSerilization.header!.keyID, "e9bc097a-ce51-4036-9562-d2ade882db0d")
        // We cannot test if the ES256 signature is equal since the value is always different,
        // instead we verify with the key
        XCTAssertTrue(try JWS.verify(jwsJson: jws, jwk: es256KeyJWK))
    }
}
