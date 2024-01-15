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
import JWA
import JWK

struct ECDH1PUJWEDecryptor: JWEDecryptor {
    
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .ecdh1PU,
        .ecdh1PUA128KW,
        .ecdh1PUA192KW,
        .ecdh1PUA256KW
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
            throw JWE.JWEError.decryptionNotSupported(
                alg: alg,
                enc: enc,
                supportedAlgs: supportedKeyManagmentAlgorithms,
                supportedEnc: supportedContentEncryptionAlgorithms
            )
        }
        
        guard let senderKey else{
            throw JWE.JWEError.missingSenderKey
        }
        
        guard let recipientKey else{
            throw JWE.JWEError.missingRecipientKey
        }
        
        guard let ephemeralKey = getEphemeralKey(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        )?.publicKey else {
            throw JWE.JWEError.missingEphemeralKey
        }
        
        guard
            let secretKeyZ = try alg
                .agreement?
                .agreeUponZ(
                    privateKey: recipientKey,
                    publicKey: senderKey,
                    ephemeralKey: ephemeralKey,
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
        
        let cek: Data
        
        if let keyDecryptor = alg.unwrapper {
            guard let encryptedKey else {
                throw JWE.JWEError.missingEncryptedKey
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
                ),
                authenticationTag: contentTag
            )
            cek = try keyDecryptor.contentKeyDecrypt(
                encryptedKey: encryptedKey,
                using: .init(keyType: .octetSequence, key: sharedKey),
                arguments: []
            )
        } else {
            cek = try deriveSharedKey(
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
                ),
                authenticationTag: nil,
                isDirect: true
            )
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
        partyVInfo: Data?,
        authenticationTag: Data?,
        isDirect: Bool = false
    ) throws -> Data {
        guard
            let derivation = keyAlgorithm.derivation
        else {
            throw JWE.JWEError.internalErrorDerivationNotAvailableFor(alg: keyAlgorithm)
        }
        let algorithmID: Data
        if isDirect {
            algorithmID = encodingAlgorithm.rawValue.data(using: .ascii) ?? .init()
        } else {
            algorithmID = keyAlgorithm.rawValue.data(using: .ascii) ?? .init()
        }
        
        let tagData: Data
        if isDirect {
            tagData = .init()
        } else {
            tagData = authenticationTag ?? .init()

        }

        return try derivation.deriveKey(
            key: sharedKey,
            keyLengthInBits: keyLengthInBits,
            algorithmId: algorithmID,
            partyUInfo: partyUInfo ?? .init(),
            partyVInfo: partyVInfo ?? .init(),
            tag: tagData,
            other: [:]
        )
    }
    
    private func sharedKeyLength(
        keyManagementAlgo: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm
    ) throws -> Int {
        switch keyManagementAlgo {
        case .ecdh1PU:
            return encryptionAlgorithm.keySizeInBits
        case .ecdh1PUA128KW:
            return 128
        case .ecdh1PUA192KW:
            return 192
        case .ecdh1PUA256KW:
            return 256
        default:
            throw JWE.JWEError.unsupportedOperation(alg: keyManagementAlgo, enc: encryptionAlgorithm)
        }
    }
}
