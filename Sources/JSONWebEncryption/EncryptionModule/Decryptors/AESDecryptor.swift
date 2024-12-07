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

struct AESJWEDecryptor: JWEDecryptor {
    var supportedKeyManagementAlgorithms: [KeyManagementAlgorithm] = [
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
    
    func decrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        protectedHeader: P?,
        unprotectedHeader: U?,
        cipher: Data,
        recipientHeader: R?,
        encryptedKey: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        additionalAuthenticationData: Data?,
        senderKey: JWK?,
        recipientKey: JWK?,
        password: Data?
    ) throws -> Data {
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
            supportedKeyAlgorithms: supportedKeyManagementAlgorithms,
            supportedContentEncryptionAlgorithms: supportedContentEncryptionAlgorithms
        ) else {
            throw JWE.JWEError.decryptionNotSupported(
                alg: alg,
                enc: enc,
                supportedAlgs: supportedKeyManagementAlgorithms,
                supportedEnc: supportedContentEncryptionAlgorithms
            )
        }
        
        guard let kek = recipientKey else{
            throw JWE.JWEError.missingKek
        }
        
        guard let encryptedKey else {
            throw JWE.JWEError.missingEncryptedKey
        }
        
        guard let contentIv = initializationVector else {
            throw JWE.JWEError.missingContentIV
        }
        
        guard let contentTag = authenticationTag else {
            throw JWE.JWEError.missingContentAuthenticationTag
        }
        
        let cek: Data
        switch alg {
        case .a128KW, .a192KW, .a256KW:
            guard
                let cekAux = try alg.unwrapper?.contentKeyDecrypt(
                    encryptedKey: encryptedKey,
                    using: kek,
                    arguments: []
                )
            else {
                throw JWE.JWEError.internalErrorUnWrapperMissingFor(alg: alg)
            }
            cek = cekAux
        case .a128GCMKW, .a192GCMKW, .a256GCMKW:
            guard let keyIv = getKeyEncryptionInitializationVector(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            ) else {
                throw JWE.JWEError.missingKeyIV
            }
            guard let keyTag =  getKeyEncryptionAuthenticationTag(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            ) else {
                throw JWE.JWEError.missingKeyTag
            }
            guard
                let cekAux = try alg.unwrapper?.contentKeyDecrypt(
                    encryptedKey: encryptedKey,
                    using: kek,
                    arguments: [
                        .initializationVector(keyIv),
                        .authenticationTag(keyTag)
                    ]
                )
            else {
                throw JWE.JWEError.internalErrorUnWrapperMissingFor(alg: alg)
            }
            cek = cekAux
        default:
            throw JWE.JWEError.unsupportedOperation(alg: alg, enc: enc)
        }
        
        let aad = try AAD.computeAAD(header: protectedHeader, aad: additionalAuthenticationData)
        
        let payload = try enc.decryptor.decrypt(
            cipher: cipher,
            using: cek,
            arguments: [
                .initializationVector(contentIv),
                .additionalAuthenticationData(aad),
                .authenticationTag(contentTag)
            ]
        )
        
        return try getContentCompressionAlg(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        )?.decompressor.decompress(input: payload) ?? payload
    }
}
