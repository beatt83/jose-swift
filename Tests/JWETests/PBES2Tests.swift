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


@testable import JSONWebEncryption
import XCTest

final class PBES2Tests: XCTestCase {

    func testPBES2_HS256_A128KW() throws {
        let password = try "secret".tryToData()
        let payload = "Hello world!"
        
        let encryption = try PasswordBasedJWEEncryptor().encrypt(
            payload: payload.tryToData(),
            senderKey: nil,
            recipientKey: nil,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .pbes2HS256A128KW,
                encodingAlgorithm: .a128GCM
            ),
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            recipientHeader: nil as DefaultJWEHeaderImpl?,
            cek: nil,
            initializationVector: nil,
            additionalAuthenticationData: nil,
            password: password,
            saltLength: 16,
            iterationCount: 8192,
            hasMultiRecipients: false
        )
        
        let decryption = try PasswordBasedJWEDecryptor().decrypt(
            protectedHeader: encryption.protectedHeader,
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            cipher: encryption.cipherText,
            recipientHeader: encryption.recipientHeader,
            encryptedKey: encryption.encryptedKey,
            initializationVector: encryption.initializationVector,
            authenticationTag: encryption.authenticationTag,
            additionalAuthenticationData: encryption.additionalAuthenticationData,
            senderKey: nil,
            recipientKey: nil,
            sharedKey: nil,
            password: password
        )
        
        XCTAssertEqual(payload, try decryption.tryToString())
    }
    
    func testPBES2_HS384_A192KW() throws {
        let password = try "secret".tryToData()
        let payload = "Hello world!"
        
        let encryption = try PasswordBasedJWEEncryptor().encrypt(
            payload: payload.tryToData(),
            senderKey: nil,
            recipientKey: nil,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .pbes2HS384A192KW,
                encodingAlgorithm: .a128CBCHS256
            ),
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            recipientHeader: nil as DefaultJWEHeaderImpl?,
            cek: nil,
            initializationVector: nil,
            additionalAuthenticationData: nil,
            password: password,
            saltLength: 16,
            iterationCount: 8192,
            hasMultiRecipients: false
        )
        
        let decryption = try PasswordBasedJWEDecryptor().decrypt(
            protectedHeader: encryption.protectedHeader,
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            cipher: encryption.cipherText,
            recipientHeader: encryption.recipientHeader,
            encryptedKey: encryption.encryptedKey,
            initializationVector: encryption.initializationVector,
            authenticationTag: encryption.authenticationTag,
            additionalAuthenticationData: encryption.additionalAuthenticationData,
            senderKey: nil,
            recipientKey: nil,
            sharedKey: nil,
            password: password
        )
        
        XCTAssertEqual(payload, try decryption.tryToString())
    }
    
    func testPBES2_HS512_A256KW() throws {
        let password = try "secret".tryToData()
        let payload = "Hello world!"
        
        let encryption = try PasswordBasedJWEEncryptor().encrypt(
            payload: payload.tryToData(),
            senderKey: nil,
            recipientKey: nil,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .pbes2HS512A256KW,
                encodingAlgorithm: .a256CBCHS512
            ),
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            recipientHeader: nil as DefaultJWEHeaderImpl?,
            cek: nil,
            initializationVector: nil,
            additionalAuthenticationData: nil,
            password: password,
            saltLength: 16,
            iterationCount: 8192,
            hasMultiRecipients: false
        )
        
        let decryption = try PasswordBasedJWEDecryptor().decrypt(
            protectedHeader: encryption.protectedHeader,
            unprotectedHeader: nil as DefaultJWEHeaderImpl?,
            cipher: encryption.cipherText,
            recipientHeader: encryption.recipientHeader,
            encryptedKey: encryption.encryptedKey,
            initializationVector: encryption.initializationVector,
            authenticationTag: encryption.authenticationTag,
            additionalAuthenticationData: encryption.additionalAuthenticationData,
            senderKey: nil,
            recipientKey: nil,
            sharedKey: nil,
            password: password
        )
        
        XCTAssertEqual(payload, try decryption.tryToString())
    }
    
    func testJWEPBES2_HS512_A256KW() throws {
        let password = try "secret".tryToData()
        let payload = "Hello world!"
        
        let jweString = try JWE.init(
            payload: payload.tryToData(),
            keyManagementAlg: .pbes2HS512A256KW,
            encryptionAlgorithm: .a256CBCHS512,
            password: password,
            saltLength: 16,
            iterationCount: 8192
        ).compactSerialization()
        
        let decrypted = try JWE.decrypt(
            compactString: jweString,
            password: password
        )
        
        XCTAssertEqual(payload, try decrypted.tryToString())
    }
}
