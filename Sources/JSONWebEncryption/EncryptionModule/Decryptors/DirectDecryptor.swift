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

struct DirectJWEDecryptor: JWEDecryptor {
    
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .direct
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
        sharedKey: JWK?
    ) throws -> Data {
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
            throw JWE.JWEError.decryptionNotSupported(
                alg: nil,
                enc: enc,
                supportedAlgs: supportedKeyManagmentAlgorithms,
                supportedEnc: supportedContentEncryptionAlgorithms
            )
        }
        
        guard let contentIv = initializationVector else {
            throw JWE.JWEError.missingContentIV
        }
        
        guard let contentTag = authenticationTag else {
            throw JWE.JWEError.missingContentAuthenticationTag
        }
        
        guard let cek = sharedKey?.key else {
            throw JWE.JWEError.missingCek
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
