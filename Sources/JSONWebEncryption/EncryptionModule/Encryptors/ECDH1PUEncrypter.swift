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

struct ECDH1PUJWEEncryptor: JWEEncryptor {
    let masterEphemeralKey: Bool
    
    let supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .ecdh1PU,
        .ecdh1PUA128KW,
        .ecdh1PUA192KW,
        .ecdh1PUA256KW
    ]
    
    let supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [
        .a128GCM,
        .a192GCM,
        .a256GCM,
        .a128CBCHS256,
        .a192CBCHS384,
        .a256CBCHS512
    ]
    
    init(masterEphemeralKey: Bool = false) {
        self.masterEphemeralKey = masterEphemeralKey
    }
    
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
        ephemeralKey: JWK?,
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
        
        guard let senderKey else {
            throw JWE.JWEError.missingSenderKey
        }
        
        guard let recipientKey else {
            throw JWE.JWEError.missingRecipientKey
        }
        
        guard let ephemeralKeyPair = try ephemeralKey ??
                senderKey.keyGeneration?.generateKeyPairJWK(purpose: .keyAgreement)
        else {
            throw JWE.JWEError.missingEphemeralKey
        }
        
        var finalProtectedHeader = protectedHeader
        ?? recipientHeader.map { P.init(key: recipientKey, header: $0) }
        ?? P.init(from: recipientKey)
        
        var finalRecipientHeader = recipientHeader
        ?? protectedHeader.map { R.init(key: recipientKey, header: $0) }
        ?? R.init(from: recipientKey)
        
        if masterEphemeralKey || !hasMultiRecipients {
            finalProtectedHeader.ephemeralPublicKey = ephemeralKeyPair.publicKey
        } else {
            finalRecipientHeader.ephemeralPublicKey = ephemeralKeyPair.publicKey
        }
        
        guard
            let secretKeyZ = try alg
                .agreement?
                .agreeUponZ(
                    privateKey: senderKey,
                    publicKey: recipientKey,
                    ephemeralKey: ephemeralKeyPair,
                    sender: true
                )
        else {
            throw JWE.JWEError.internalErrorAgreementNotAvailableFor(alg: alg)
        }
        
        let aad = try AAD.computeAAD(header: finalProtectedHeader, aad: additionalAuthenticationData)
        return try encryptWithZ(
            payload: payload,
            keyZ: secretKeyZ,
            protectedHeader: finalProtectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: finalRecipientHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: aad,
            ephemeralKey: ephemeralKeyPair
        )
    }
    
    private func encryptWithZ<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        keyZ: Data,
        protectedHeader: P?,
        unprotectedHeader: U?,
        recipientHeader: R?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data,
        ephemeralKey: JWK
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
        
        if let keyEncryptor = alg.wrapper {
            let cek = try cek ?? enc.encryptor.generateCEK()
            let contentIv = try initializationVector ??
            enc.encryptor.generateInitializationVector()
            
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
            
            let encryptionResult = try enc.encryptor.encrypt(
                payload: finalPayload,
                using: cek,
                arguments: [
                    .initializationVector(contentIv),
                    .additionalAuthenticationData(additionalAuthenticationData)
                ]
            )

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
                authenticationTag: encryptionResult.authenticationData,
                isDirect: false
            )
            
            let encryptedKey = try keyEncryptor.contentKeyEncrypt(
                cek: cek,
                using: .init(keyType: .octetSequence, key: sharedKey),
                arguments: [
                    .authenticationTag(encryptionResult.authenticationData)
            ])

            return .init(
                protectedHeader: protectedHeader,
                recipientHeader: recipientHeader ?? protectedHeader.map { R.init(from: $0) },
                cipherText: encryptionResult.cipher,
                encryptedKey: encryptedKey.encryptedKey,
                additionalAuthenticationData: additionalAuthenticationData,
                initializationVector: contentIv,
                authenticationTag: encryptionResult.authenticationData,
                ephemeralKey: ephemeralKey
            )
        } else {
            let cek = try deriveSharedKey(
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
            
            let contentIv = try initializationVector
            ?? enc.encryptor.generateInitializationVector()
            
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
            
            let encryptionResult = try enc.encryptor.encrypt(
                payload: finalPayload,
                using: cek,
                arguments: [
                    .initializationVector(contentIv),
                    .additionalAuthenticationData(additionalAuthenticationData)
                ]
            )
            
            return .init(
                protectedHeader: protectedHeader,
                recipientHeader: recipientHeader ?? protectedHeader.map { R.init(from: $0) },
                cipherText: encryptionResult.cipher,
                encryptedKey: nil,
                additionalAuthenticationData: additionalAuthenticationData,
                initializationVector: contentIv,
                authenticationTag: encryptionResult.authenticationData,
                ephemeralKey: ephemeralKey
            )
        }
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
        
        return try derivation.deriveKey(arguments: [
            .key(sharedKey),
            .keyLengthInBits(keyLengthInBits),
            .algorithmId(algorithmID),
            .partyUInfo(partyUInfo ?? .init()),
            .partyVInfo(partyVInfo ?? .init()),
            .tag(tagData)
        ])
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
