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
import Tools

struct AESJWEEncryptor: JWEEncryptor {
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .a128KW,
        .a192KW,
        .a256KW,
        .a128GCMKW,
        .a192GCMKW,
        .a256GCMKW
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
        password: Data?,
        saltLength: Int?,
        iterationCount: Int?,
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
        
        guard
            let wrapper = alg.wrapper
        else {
            throw JWE.JWEError.internalErrorWrapperMissingFor(alg: alg)
        }
        
        var finalRecipientHeader = recipientHeader
        ?? protectedHeader.map { R.init(from: $0) }
        ?? R.init()
        
        var finalProtectedHeader = protectedHeader
        ?? recipientHeader.map { P.init(from: $0) }
        ?? P.init()
        
        let cek = try cek ?? enc.encryptor.generateCEK()
        
        let encryptedKey: Data
        switch alg {
        case .a128KW, .a192KW, .a256KW:
            let result = try wrapper.contentKeyEncrypt(
                cek: cek,
                using: recipientKey,
                arguments: []
            )
            encryptedKey = result.encryptedKey
        case .a128GCMKW, .a192GCMKW, .a256GCMKW:
            let keyIv = getKeyEncryptionInitializationVector(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            )
            
            let result = try wrapper.contentKeyEncrypt(
                cek: cek,
                using: recipientKey,
                arguments: [
                    keyIv.map { .initializationVector($0) }
                ].compactMap { $0 }
            )
            if let keyIv = result.initializationVector, let tag = result.authenticationTag {
                if hasMultiRecipients {
                    finalRecipientHeader.initializationVector = keyIv
                    finalRecipientHeader.authenticationTag = tag
                } else {
                    finalProtectedHeader.initializationVector = keyIv
                    finalProtectedHeader.authenticationTag = tag
                }
            }
            encryptedKey = result.encryptedKey
        default:
            throw JWE.JWEError.unsupportedOperation(alg: alg, enc: enc)
        }
        
        let contentIv = try initializationVector
        ?? enc.encryptor.generateInitializationVector()
        let aad = try AAD.computeAAD(header: finalProtectedHeader, aad: additionalAuthenticationData)
        
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

        return .init(
            protectedHeader: finalProtectedHeader,
            recipientHeader: finalRecipientHeader,
            cipherText: encryption.cipher,
            encryptedKey: encryptedKey,
            additionalAuthenticationData: aad,
            initializationVector: contentIv,
            authenticationTag: encryption.authenticationData
        )
    }
}
