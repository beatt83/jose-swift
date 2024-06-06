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

final class ECDH1PUTests: XCTestCase {
    func testECDH1PUCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingES256Pair
        let bobKey = JWK.testingES256Pair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PU
        let encAlg = ContentEncryptionAlgorithm.a128GCM
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testECDH1PUA128KWCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingES256Pair
        let bobKey = JWK.testingES256Pair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA128KW
        let encAlg = ContentEncryptionAlgorithm.a128CBCHS256
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testECDH1PUA192KWCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingES256Pair
        let bobKey = JWK.testingES256Pair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA192KW
        let encAlg = ContentEncryptionAlgorithm.a128CBCHS256
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testECDH1PUA256KWCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingES256Pair
        let bobKey = JWK.testingES256Pair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA256KW
        let encAlg = ContentEncryptionAlgorithm.a128GCM
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload, decrypted)
    }
    
    func testECDH1PUA256KWCurve25519Cycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingCurve25519KPair
        let bobKey = JWK.testingCurve25519KPair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA256KW
        let encAlg = ContentEncryptionAlgorithm.a256CBCHS512
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload.toHexString(), decrypted.toHexString())
    }
    
    func testECDH1PUA256KW_C20PKWCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingCurve25519KPair
        let bobKey = JWK.testingCurve25519KPair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA256KW
        let encAlg = ContentEncryptionAlgorithm.c20PKW
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload.toHexString(), decrypted.toHexString())
    }
    
    func testECDH1PUA256KW_XC20PKWCycle() throws {
        let payload = try "Test".tryToData()
        let aliceKey = JWK.testingCurve25519KPair
        let bobKey = JWK.testingCurve25519KPair
        
        let keyAlg = KeyManagementAlgorithm.ecdh1PUA256KW
        let encAlg = ContentEncryptionAlgorithm.xC20PKW
        
        let header = try DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyAlg,
            encodingAlgorithm: encAlg,
            agreementPartyUInfo: Base64URL.encode("Alice".tryToData()).tryToData(),
            agreementPartyVInfo: Base64URL.encode("Bob".tryToData()).tryToData()
        )
        
        let jwe = try ECDH1PUJWEEncryptor().encrypt(
            payload: payload,
            senderKey: aliceKey,
            recipientKey: bobKey,
            protectedHeader: header
        )
        
        let decrypted = try ECDH1PUJWEDecryptor().decrypt(
            protectedHeader: jwe.protectedHeader!,
            cipher: jwe.cipherText,
            encryptedKey: jwe.encryptedKey,
            initializationVector: jwe.initializationVector,
            authenticationTag: jwe.authenticationTag,
            additionalAuthenticationData: jwe.additionalAuthenticationData,
            senderKey: aliceKey,
            recipientKey: bobKey
        )
        
        XCTAssertEqual(payload.toHexString(), decrypted.toHexString())
    }
}
