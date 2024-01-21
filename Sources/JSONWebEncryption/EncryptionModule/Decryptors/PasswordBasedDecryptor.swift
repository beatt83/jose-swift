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

struct PasswordBasedJWEDecryptor: JWEDecryptor {
    var supportedKeyManagementAlgorithms: [KeyManagementAlgorithm] = [
        .pbes2HS256A128KW,
        .pbes2HS384A192KW,
        .pbes2HS512A256KW
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
        sharedKey: JWK?,
        password: Data?
    ) throws -> Data {
        guard let iterationCount = getSaltCount(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) else {
            throw JWE.JWEError.missingSaltCount
        }
        
        guard let saltInput = getSaltInput(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) else {
            throw JWE.JWEError.missingSaltInput
        }
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
        
        guard let encryptedKey else {
            throw JWE.JWEError.missingEncryptedKey
        }
        
        guard let contentIv = initializationVector else {
            throw JWE.JWEError.missingContentIV
        }
        
        guard let contentTag = authenticationTag else {
            throw JWE.JWEError.missingContentAuthenticationTag
        }
        
        guard let derivator = alg.derivation else {
            throw JWE.JWEError.internalErrorDerivationNotAvailableFor(alg: alg)
        }
        
        let salt = try alg.rawValue.tryToData() + [0x00] + saltInput
        
        let derivedKey = try derivator.deriveKey(arguments: [
            .password(password ?? .init()),
            .saltInput(salt),
            .saltCount(iterationCount)
        ])
        
        guard let unwrapper = alg.unwrapper else {
            throw JWE.JWEError.internalErrorUnWrapperMissingFor(alg: alg)
        }
        
        let cek = try unwrapper.contentKeyDecrypt(
            encryptedKey: encryptedKey,
            using: .init(keyType: .octetSequence, key: derivedKey),
            arguments: []
        )
        
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
