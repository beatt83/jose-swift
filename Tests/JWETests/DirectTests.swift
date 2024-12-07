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

import XCTest
@testable import JSONWebEncryption
import JSONWebAlgorithms
import JSONWebKey
import Tools

final class DirectTests: XCTestCase {
    func testDirectCycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.direct
        let encAlg = ContentEncryptionAlgorithm.a256CBCHS512
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let secretKey = try encAlg.encryptor.generateCEK()
        
        let jwe = try DirectJWEEncryptor().encrypt(
            payload: payload,
            protectedHeader: header,
            cek: secretKey
        )
        
        let decrypted = try DirectJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: .init(keyType: .octetSequence, key: secretKey)
        )
        
        XCTAssertEqual(payload, decrypted)
    }
}
