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

import Foundation
import JSONWebAlgorithms
import JSONWebKey

struct RSAJWEEncryptor: JWEEncryptor {
    
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .rsaOAEP256,
        .rsaOAEP,
        .rsa1_5
    ]
    
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [
        .a128GCM,
        .a192GCM,
        .a256GCM,
        .a128CBCHS256,
        .a192CBCHS384,
        .a256CBCHS512
    ]
    
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK?,
        recipientKey: JWK?,
        protectedHeader: P?,
        unprotectedHeader: U?,
        recipientHeader: R?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data?,
        hasMultiRecipients: Bool
    ) throws -> JWEParts<P, R> {
        guard let alg = getKeyAlgorithm(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) else {
            throw JWE.JWEError.missingKeyAlgorithm
        }
        
        guard let enc = getEncoding(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) else {
            throw JWE.JWEError.missingContentEncryptionAlgorithm
        }
        
        guard isSupported(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader,
            supportedKeyAlgorithms: supportedKeyManagmentAlgorithms,
            supportedContentEncryptionAlgorithms: supportedContentEncryptionAlgorithms
        ) else {
            throw JWE.JWEError.encryptionNotSupported(
                alg: alg,
                enc: enc,
                supportedAlgs: supportedKeyManagmentAlgorithms,
                supportedEnc: supportedContentEncryptionAlgorithms
            )
        }
        
        guard let recipientKey else {
            throw JWE.JWEError.missingRecipientKey
        }
        
        let cek = try cek ?? enc.encryptor.generateCEK()
        let result = try alg.wrapper?.contentKeyEncrypt(
            cek: cek,
            using: recipientKey,
            arguments: []
        )
        
        let contentIv = try initializationVector
        ?? enc.encryptor.generateInitializationVector()
        let aad =  try AAD.computeAAD(header: protectedHeader, aad: additionalAuthenticationData)
        
        let finalPayload: Data
        if let compressAlg = getContentCompressionAlg(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) {
            finalPayload = try compressAlg.compressor.compress(input: payload)
        } else {
            finalPayload = payload
        }
        
        let encryption = try enc.encryptor.encrypt(
            payload: finalPayload,
            using: cek,
            arguments: [
                .initializationVector(contentIv),
                .additionalAuthenticationData(aad)
            ]
        )
        
        let finalHeader = recipientHeader
        ?? protectedHeader.map { R.init(from: $0) }
        ?? R.init()
        
        return .init(
            protectedHeader: protectedHeader,
            recipientHeader: finalHeader,
            cipherText: encryption.cipher,
            encryptedKey: result?.encryptedKey,
            additionalAuthenticationData: aad,
            initializationVector: contentIv,
            authenticationTag: encryption.authenticationData
        )
    }
}
