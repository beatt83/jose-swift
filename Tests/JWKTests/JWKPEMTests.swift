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

import Crypto
import CryptoSwift
import JSONWebAlgorithms
@testable import JSONWebKey
import XCTest
import Tools

final class JWKPEMTests: XCTestCase {
    func testECPublicKeySecp256k1() throws {
        // This sample EC public key PEM produces secp256k1.
        let ecSecp256k1PEM = """
        -----BEGIN PUBLIC KEY-----
        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEqKx6+F/qW1GvAx9dAwJPVZyqA8X2+6fM
        T0H/t8a/cWwVDWCR7qIL6E6Z+zksX6TrD7G+Roc9zj+gC8QY+UcQlw==
        -----END PUBLIC KEY-----
        """
        let jwk = try JWK(pem: ecSecp256k1PEM)
        XCTAssertEqual(jwk.keyType, .ellipticCurve, "Expected an elliptic curve key type")
        XCTAssertNotNil(jwk.x, "x coordinate should not be nil")
        XCTAssertNotNil(jwk.y, "y coordinate should not be nil")
        // This test expects secp256k1 (modify mapping in JWK.mapCurveOID if needed)
        XCTAssertEqual(jwk.curve, .secp256k1, "Expected curve to be secp256k1")
    }
    
    func testECPrivateKeyP256() throws {
        // This sample PEM should represent a P-256 key.
        // (Ensure this PEM string is valid and that the algorithm parameters contain the OID 1.2.840.10045.3.1.7)
        let ecP256PEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIOVCd67H8/C2oh7/0V/vs/nbNzHnxaVzI8beEfVTRtNcoAoGCCqGSM49
        AwEHoUQDQgAEMAHP6cs+PlgUMnMKH66dJK9qcDCs4UdUTwgArGAjEBTvZAE705fe
        cO4QS9hJGCQCU0/BEXOtUkeuiKJ7Wxag1w==
        -----END EC PRIVATE KEY-----
        """
        let jwk = try JWK(pem: ecP256PEM)
        XCTAssertEqual(jwk.keyType, .ellipticCurve, "Expected an elliptic curve key type")
        XCTAssertEqual(jwk.curve, .p256, "Expected curve to be P-256")
        XCTAssertNoThrow(try jwk.cryptoKitRepresentation(type: P256.Signing.PrivateKey.self))
    }
    
    func testECPublicKeyP256() throws {
        // This sample PEM should represent a P-256 key.
        // (Ensure this PEM string is valid and that the algorithm parameters contain the OID 1.2.840.10045.3.1.7)
        let ecP256PEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMAHP6cs+PlgUMnMKH66dJK9qcDCs
        4UdUTwgArGAjEBTvZAE705fecO4QS9hJGCQCU0/BEXOtUkeuiKJ7Wxag1w==
        -----END PUBLIC KEY-----
        """
        let jwk = try JWK(pem: ecP256PEM)
        XCTAssertEqual(jwk.keyType, .ellipticCurve, "Expected an elliptic curve key type")
        XCTAssertNotNil(jwk.x, "x coordinate should not be nil")
        XCTAssertNotNil(jwk.y, "y coordinate should not be nil")
        XCTAssertEqual(jwk.curve, .p256, "Expected curve to be P-256")
        XCTAssertNoThrow(try jwk.cryptoKitRepresentation(type: P256.Signing.PublicKey.self))
    }
    
    func testRSAPrivateKey() throws {
        // A sample RSA public key in SubjectPublicKeyInfo format.
        // This PEM string was generated with proper base64 encoding.
        let rsaPEM = """
        -----BEGIN PRIVATE KEY-----
        MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKm+VKkRVy0ucnOe
        vPeJ4jcQGg0gCz2HdvDg+GWYZTtx2AJ8BmHaAg2sQ7iIasiICcNzXq4mltbvUq0k
        tp7U9isGj7W2uBB9KVpD8nkgtHeEsNrR5WzXDPfbpzH5AuZ+xUTR3iht3LIJ4Sd8
        JM79ysuHkw1ZUmMqSRi5h0dF/4OLAgMBAAECgYBKl9mccoJc2IxzQs7H+U/v4qOQ
        IQTPhTg/op2GB/J0rRLABMDJP4SnfYxFC63hcebYfVqeLVccHQ+4Buo54lxK1L6r
        GggZOVz13BfMRZq24ZWhIAESuj74onR/mW8PqE2XJn7b9V7w/36YHbJTMiQriZtu
        DNmx6defUH4X+pTAAQJBANiGhkYgFm0ZYrYL2iGUCFRV4lJdz3ygUrcw9zGTU4Yx
        atyY1DVfR5nImEReo6Go57Wo6jxqwSP4bSpfMCGbvUsCQQDIsHCkefBg7o073AW0
        QXYMZ3ZQk63kgc+DEKooTRNVC+RN0mRBEY4B4Jk01juIlRxNTTKvClibR3yNweZI
        ZqrBAkEArX/N5C8eCTnIMRt6JGHb8sgG2/0znydQYF4qFV16FhNPD4iesk2wr/de
        m5pB/+26DYRWfScFsG8F+mffx25l1QJADx/U7WBPME7qD+fN+j6wsdCeRwZKJZ1u
        0RbRbAYa/d7OjtrbOVgkVpnhkezPQcTTBDRcLHrgIJurlFdXjn9GQQJAFlDOz9zC
        HGkapt/RGdFiU+J0+CHW9PBAeekvekw1I+SVSFZUK+fr3HvljhA5E0L7FU2VIQ3L
        G1KxboX9sECU5A==
        -----END PRIVATE KEY-----
        """
        let jwk = try JWK(pem: rsaPEM)
        XCTAssertEqual(jwk.keyType, .rsa, "Expected an RSA key type")
        XCTAssertNotNil(jwk.n, "Modulus (n) should not be nil")
        XCTAssertNotNil(jwk.e, "Exponent (e) should not be nil")
        guard let n = jwk.n, let e = jwk.e, let d = jwk.d, let p = jwk.p, let q = jwk.q else {
            XCTFail()
            return
        }
        XCTAssertNoThrow(try RSA(
            n: BigUInteger(n),
            e: BigUInteger(e),
            d: BigUInteger(d),
            p: BigUInteger(p),
            q: BigUInteger(q)
        ))
    }
    
    func testRSAPublicKey() throws {
        // A sample RSA public key in SubjectPublicKeyInfo format.
        // This PEM string was generated with proper base64 encoding.
        let rsaPEM = """
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpvlSpEVctLnJznrz3ieI3EBoN
        IAs9h3bw4PhlmGU7cdgCfAZh2gINrEO4iGrIiAnDc16uJpbW71KtJLae1PYrBo+1
        trgQfSlaQ/J5ILR3hLDa0eVs1wz326cx+QLmfsVE0d4obdyyCeEnfCTO/crLh5MN
        WVJjKkkYuYdHRf+DiwIDAQAB
        -----END PUBLIC KEY-----

        """
        let jwk = try JWK(pem: rsaPEM)
        XCTAssertEqual(jwk.keyType, .rsa, "Expected an RSA key type")
        XCTAssertNotNil(jwk.n, "Modulus (n) should not be nil")
        XCTAssertNotNil(jwk.e, "Exponent (e) should not be nil")
    }
}
