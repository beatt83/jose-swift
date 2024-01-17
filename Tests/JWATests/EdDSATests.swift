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

@testable import JSONWebAlgorithms
import JSONWebKey
import XCTest

final class EdDSATests: XCTestCase {

    func testEdDSACycle() throws {
        let payload = "Test".data(using: .utf8)!
        let key = JWK.testingCurve25519KPair
        let signature = try EdDSASigner().sign(data: payload, key: key)
        XCTAssertTrue(try EdDSAVerifier().verify(
            data: payload,
            signature: signature,
            key: key
        ))
    }
}
