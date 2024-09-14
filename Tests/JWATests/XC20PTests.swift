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

final class XC20PTests: XCTestCase {

    func testXC20PCycle() throws {
        let payload = "Test".data(using: .utf8)!
        let encryptor = ContentEncryptionAlgorithm.xC20P.encryptor
        let decryptor = ContentEncryptionAlgorithm.xC20P.decryptor
        let key = try encryptor.generateCEK()
        let iv = try encryptor.generateInitializationVector()
        let aad = Data()
        
        let encryption = try encryptor.encrypt(payload: payload, using: key, arguments: [
            .initializationVector(iv),
            .additionalAuthenticationData(aad)
        ])
        
        let decryption = try decryptor.decrypt(cipher: encryption.cipher, using: key, arguments: [
            .initializationVector(iv),
            .authenticationTag(encryption.authenticationData),
            .additionalAuthenticationData(aad)
        ])
        
        XCTAssertEqual(try! payload.tryToString(), try! decryption.tryToString())
    }
}
