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

struct ECDHJWEEncryptor: JWEEncryptor {
    let masterEphemeralKey: Bool
    
    let supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
        .ecdhES,
        .ecdhESA128KW,
        .ecdhESA192KW,
        .ecdhESA256KW
    ]
    
    let supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [
        .a128GCM,
        .a192GCM,
        .a256GCM,
        .a128CBCHS256,
        .a192CBCHS384,
        .a256CBCHS512,
        .c20P,
        .xC20P
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
    ) throws -> JWEParts<P, R>{
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
        
        guard let ephemeralKeyPair = try ephemeralKey
                ?? recipientKey.keyGeneration?.generateKeyPairJWK(purpose: .keyAgreement)
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
                    privateKey: ephemeralKeyPair,
                    publicKey: recipientKey,
                    ephemeralKey: nil,
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
            additionalAuthenticationData: aad
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
        additionalAuthenticationData: Data
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
        
        let usingCek: Data
        let encryptedKey: Data?
        
        if let keyEncryptor = alg.wrapper {
            usingCek = try cek ?? enc.encryptor.generateCEK()
            let result = try keyEncryptor.contentKeyEncrypt(
                cek: usingCek,
                using: .init(keyType: .octetSequence, key: sharedKey),
                arguments: []
            )
            encryptedKey = result.encryptedKey
        } else {
            usingCek = sharedKey
            encryptedKey = nil
        }
        
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
            using: usingCek,
            arguments: [
                .initializationVector(contentIv),
                .additionalAuthenticationData(additionalAuthenticationData)
            ]
        )
        
        return .init(
            protectedHeader: protectedHeader,
            recipientHeader: recipientHeader ?? protectedHeader.map { R.init(from: $0) },
            cipherText: encryptionResult.cipher,
            encryptedKey: encryptedKey,
            additionalAuthenticationData: additionalAuthenticationData,
            initializationVector: contentIv,
            authenticationTag: encryptionResult.authenticationData
        )
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
