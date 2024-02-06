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

struct PasswordBasedJWEEncryptor: JWEEncryptor {
    // Min byte size of a salt input
    let minSaltByteLength = 8
    // Min recommended interation count
    let minInterationCount = 1000
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] = [
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
        let iterationCount = getSaltCount(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) ?? iterationCount ?? 1000
        
        guard iterationCount >= minInterationCount else {
            throw JWE.JWEError.invalidSaltCount
        }
        
        let saltInput = try getSaltInput(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ) ?? SecureRandom.secureRandomData(count: saltLength ?? 8)
        
        guard saltInput.count >= minSaltByteLength else {
            throw JWE.JWEError.invalidSaltLength
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
        
        var finalRecipientHeader = recipientHeader
        ?? protectedHeader.map { R.init(from: $0) }
        ?? R.init()
        
        var finalProtectedHeader = protectedHeader
        ?? recipientHeader.map { P.init(from: $0) }
        ?? P.init()
        
        guard let derivator = alg.derivation else {
            throw JWE.JWEError.internalErrorDerivationNotAvailableFor(alg: alg)
        }
        
        let salt = try alg.rawValue.tryToData() + [0x00] + saltInput
        
        let derivedKey = try derivator.deriveKey(arguments: [
            .password(password ?? .init()),
            .saltInput(salt),
            .saltCount(iterationCount)
        ])
        
        if hasMultiRecipients {
            finalRecipientHeader.pbes2SaltInput = saltInput
            finalRecipientHeader.pbes2SaltCount = iterationCount
        } else {
            finalProtectedHeader.pbes2SaltInput = saltInput
            finalProtectedHeader.pbes2SaltCount = iterationCount
        }
        
        let cek = try cek ?? enc.encryptor.generateCEK()
        
        guard let wrapper = alg.wrapper else {
            throw JWE.JWEError.internalErrorWrapperMissingFor(alg: alg)
        }
        
        let encryptedKey = try wrapper.contentKeyEncrypt(
            cek: cek,
            using: .init(keyType: .octetSequence, key: derivedKey),
            arguments: []
        ).encryptedKey
        
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

private func formatSalt(keyAlgorithm: KeyManagementAlgorithm, salt: Data) throws -> Data {
    let algData = try keyAlgorithm.rawValue.tryToData()
    return algData + [0x00] + salt
}
