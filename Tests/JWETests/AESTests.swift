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

final class AESTests: XCTestCase {
    func testAES128Cycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a128KW
        let encAlg = ContentEncryptionAlgorithm.a128GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 128)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testAES192Cycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a192KW
        let encAlg = ContentEncryptionAlgorithm.a192GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 192)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testAES256Cycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a256KW
        let encAlg = ContentEncryptionAlgorithm.a256GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 256)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testAES128GCMCycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a128GCMKW
        let encAlg = ContentEncryptionAlgorithm.a128GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 128)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testAES192GCMCycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a192GCMKW
        let encAlg = ContentEncryptionAlgorithm.a192GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 192)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testAES256GCMCycle() throws {
        let payload = try "Test".tryToData()
        
        let keyAlg = KeyManagementAlgorithm.a256GCMKW
        let encAlg = ContentEncryptionAlgorithm.a256GCM
        
        let header = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg
        )
        
        let sharedKey = JWK.generateKek(sizeInBits: 256)
        
        let jwe = try AESJWEEncryptor().encrypt(
            payload: payload,
            recipientKey: sharedKey,
            protectedHeader: header
        )
        
        let decrypted = try AESJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            recipientKey: sharedKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
}
