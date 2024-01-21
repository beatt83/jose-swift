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

struct ECDHJWEDecryptor: JWEDecryptor {
    
    var supportedKeyManagementAlgorithms: [KeyManagementAlgorithm] = [
        .ecdhES,
        .ecdhESA128KW,
        .ecdhESA192KW,
        .ecdhESA256KW
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
        
        guard let recipientKey else{
            throw JWE.JWEError.missingRecipientKey
        }
        
        guard
            let ephemeralKey = getEphemeralKey(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            )?.publicKey
        else {
            throw JWE.JWEError.missingEphemeralKey
        }
        
        guard
            let secretKeyZ = try alg
                .agreement?
                .agreeUponZ(
                    privateKey: recipientKey,
                    publicKey: ephemeralKey,
                    ephemeralKey: nil,
                    sender: false
                )
        else {
            throw JWE.JWEError.internalErrorAgreementNotAvailableFor(alg: alg)
        }
        
        let aad = try AAD.computeAAD(header: protectedHeader, aad: additionalAuthenticationData)
        
        return try decryptWithZ(
            keyZ: secretKeyZ,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cipher: cipher,
            recipientHeader: recipientHeader,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticationData: aad
        )
    }
    
    private func decryptWithZ<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        keyZ: Data,
        protectedHeader: P?,
        unprotectedHeader: U?,
        cipher: Data,
        recipientHeader: R?,
        encryptedKey: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        additionalAuthenticationData: Data
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
        
        guard let contentIv = initializationVector else {
            throw JWE.JWEError.missingContentIV
        }
        
        guard let contentTag = authenticationTag else {
            throw JWE.JWEError.missingContentAuthenticationTag
        }
        
        let sharedKey = try deriveSharedKey(
            sharedKey: keyZ,
            keyLengthInBits: try sharedKeyLength(
                keyManagementAlgo: alg,
                encryptionAlgorithm: enc
            ),
            keyAlgorithm: alg,
            encodingAlgorithm: enc,
            partyUInfo: getPartyUInfo(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            ),
            partyVInfo: getPartyVInfo(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            )
        )

        let cek: Data
        if let keyDecryptor = alg.unwrapper {
            guard let encryptedKey else {
                throw JWE.JWEError.missingEncryptedKey
            }
            
            cek = try keyDecryptor.contentKeyDecrypt(
                encryptedKey: encryptedKey,
                using: .init(keyType: .octetSequence, key: sharedKey),
                arguments: []
            )
        } else {
            cek = sharedKey
        }
        
        let payload = try enc.decryptor.decrypt(
            cipher: cipher,
            using: cek,
            arguments: [
                .initializationVector(contentIv),
                .authenticationTag(contentTag),
                .additionalAuthenticationData(additionalAuthenticationData)
            ]
        )
        
        return try getContentCompressionAlg(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        )?.decompressor.decompress(input: payload) ?? payload
    }
    
    private func deriveSharedKey(
        sharedKey: Data,
        keyLengthInBits: Int,
        keyAlgorithm: KeyManagementAlgorithm,
        encodingAlgorithm: ContentEncryptionAlgorithm,
        partyUInfo: Data?,
        partyVInfo: Data?
    ) throws -> Data {
        guard
            let derivation = keyAlgorithm.derivation
        else {
            throw JWE.JWEError.internalErrorDerivationNotAvailableFor(alg: keyAlgorithm)
        }
        let algorithmID: Data
        if keyAlgorithm.wrapper != nil {
            algorithmID = keyAlgorithm.rawValue.data(using: .ascii) ?? .init()
        } else {
            algorithmID = encodingAlgorithm.rawValue.data(using: .ascii) ?? .init()
        }
        
        return try derivation.deriveKey(arguments: [
            .key(sharedKey),
            .keyLengthInBits(keyLengthInBits),
            .algorithmId(algorithmID),
            .partyUInfo(partyUInfo ?? .init()),
            .partyVInfo(partyVInfo ?? .init())
        ])
    }
    
    private func sharedKeyLength(
        keyManagementAlgo: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm
    ) throws -> Int {
        switch keyManagementAlgo {
        case .ecdhES:
            return encryptionAlgorithm.keySizeInBits
        case .ecdhESA128KW:
            return 128
        case .ecdhESA192KW:
            return 192
        case .ecdhESA256KW:
            return 256
        default:
            throw JWE.JWEError.unsupportedOperation(alg: keyManagementAlgo, enc: encryptionAlgorithm)
        }
    }
}
