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
import Foundation
import JSONWebAlgorithms
import JSONWebKey
@testable import JSONWebSignature
import Tools
import XCTest

/// Regression tests for the RS256/ES256 → HS256 algorithm-confusion attack (GHSA-p5rq-3gxx-r4mh).
final class AlgConfusionTests: XCTestCase {

    /// Forges a compact JWS with an attacker-chosen header, HMAC-signed with `hmacSecret`.
    private func forgeHS256(payload: Data, hmacSecret: Data) -> String {
        let header = #"{"alg":"HS256"}"#.data(using: .utf8)!
        let signingInput = "\(Base64URL.encode(header)).\(Base64URL.encode(payload))"
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(signingInput.utf8),
            using: SymmetricKey(data: hmacSecret)
        )
        return "\(signingInput).\(Base64URL.encode(Data(mac)))"
    }

    /// The core PoC: an asymmetric **public** key supplied as `Data` must NOT be accepted as an
    /// HS256 secret. Before the fix this returned `true` (forgery accepted).
    func testPublicKeyAsDataRejectedAsHS256Secret() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation // known to the attacker

        let forged = forgeHS256(
            payload: #"{"sub":"admin"}"#.data(using: .utf8)!,
            hmacSecret: publicKeyData
        )
        let jws = try JWS(jwsString: forged)

        // No pinning: the library must refuse to interpret raw bytes as a symmetric secret.
        XCTAssertThrowsError(try jws.verify(key: publicKeyData)) { error in
            guard case JWS.JWSError.dataKeyRequiresExplicitAlgorithm = error else {
                return XCTFail("Expected dataKeyRequiresExplicitAlgorithm, got \(error)")
            }
        }
    }

    /// Even if a caller pins asymmetric algorithms, an HS256-downgraded token is rejected by the
    /// allow-list rather than verified.
    func testForgedHS256RejectedByAllowList() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let forged = forgeHS256(
            payload: #"{"sub":"admin"}"#.data(using: .utf8)!,
            hmacSecret: publicKeyData
        )
        let jws = try JWS(jwsString: forged)

        XCTAssertThrowsError(try jws.verify(key: publicKeyData, algorithms: [.ES256])) { error in
            guard case JWS.JWSError.algorithmNotAllowed = error else {
                return XCTFail("Expected algorithmNotAllowed, got \(error)")
            }
        }
    }

    /// Regression: a legitimately signed ES256 token still verifies with the public key as `Data`.
    func testLegitimateES256WithDataKeyStillVerifies() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let jws = try JWS(payload: #"{"sub":"alice"}"#.data(using: .utf8)!, key: privateKey.jwkRepresentation)

        XCTAssertTrue(try jws.verify(key: publicKeyData))
        XCTAssertTrue(try jws.verify(key: publicKeyData, algorithms: [.ES256]))
    }

    /// Regression: legitimate HMAC verification with a `Data` key still works once the caller
    /// pins the symmetric algorithm.
    func testLegitimateHS256RequiresPinnedAlgorithm() throws {
        let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let payload = #"{"sub":"bob"}"#.data(using: .utf8)!
        let genuine = forgeHS256(payload: payload, hmacSecret: secret)
        let jws = try JWS(jwsString: genuine)

        // Without pinning the symmetric interpretation is refused...
        XCTAssertThrowsError(try jws.verify(key: secret)) { error in
            guard case JWS.JWSError.dataKeyRequiresExplicitAlgorithm = error else {
                return XCTFail("Expected dataKeyRequiresExplicitAlgorithm, got \(error)")
            }
        }
        // ...but succeeds when the caller states intent.
        XCTAssertTrue(try jws.verify(key: secret, algorithms: [.HS256]))
    }
}
