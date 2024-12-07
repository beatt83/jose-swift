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

struct MultiDecryptor: JWEMultiDecryptor {
    func decrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        protectedHeader: P?,
        unprotectedHeader: U?,
        cipher: Data,
        recipients: [(header: R?, encryptedKey: Data?)],
        initializationVector: Data?,
        authenticationTag: Data?,
        senderKey: JWK?,
        recipientKey: JWK?,
        additionalAuthenticationData: Data?,
        tryAllRecipients: Bool,
        password: Data? = nil,
        encryptionModule: JWEEncryptionModule
    ) throws -> Data {
        let aad = try AAD.computeAAD(header: protectedHeader, aad: additionalAuthenticationData)
        
        guard let key = recipientKey else {
            throw JWE.JWEError.missingRecipientKey
        }
        
        guard !tryAllRecipients else {
            let recipient = try recipients.first {
                guard let alg = getKeyAlgorithm(
                    protectedHeader: protectedHeader,
                    unprotectedHeader: unprotectedHeader,
                    recipientHeader: $0.header
                ) else {
                    throw JWE.JWEError.missingKeyAlgorithm
                }
                
                return (try? encryptionModule.decryptor(alg: alg).decrypt(
                    protectedHeader: protectedHeader,
                    unprotectedHeader: unprotectedHeader,
                    cipher: cipher,
                    recipientHeader: $0.header,
                    encryptedKey: $0.encryptedKey,
                    initializationVector: initializationVector,
                    authenticationTag: authenticationTag,
                    additionalAuthenticationData: aad,
                    senderKey: senderKey,
                    recipientKey: recipientKey
                )) != nil
            }
            
            guard let recipient else {
                throw JWE.JWEError.recipientCannotBeFoundFor(jwk: key)
            }

            guard let alg = getKeyAlgorithm(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipient.header
            ) else {
                throw JWE.JWEError.missingKeyAlgorithm
            }
            
            return try encryptionModule.decryptor(alg: alg).decrypt(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                cipher: cipher,
                recipientHeader: recipient.header,
                encryptedKey: recipient.encryptedKey,
                initializationVector: initializationVector,
                authenticationTag: authenticationTag,
                additionalAuthenticationData: aad,
                senderKey: senderKey,
                recipientKey: recipientKey
            )
        }
        
        guard let recipient = getRecipient(
            recipients: recipients,
            jwk: key,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader
        ) else {
            throw JWE.JWEError.recipientCannotBeFoundFor(jwk: key)
        }
        
        guard let alg = getKeyAlgorithm(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipient.header
        ) else {
            throw JWE.JWEError.missingKeyAlgorithm
        }
        
        return try encryptionModule.decryptor(alg: alg).decrypt(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cipher: cipher,
            recipientHeader: recipient.header,
            encryptedKey: recipient.encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticationData: aad,
            senderKey: senderKey,
            recipientKey: recipientKey
        )
    }
}

private func getRecipient<R: JWERegisteredFieldsHeader>(
    recipients: [(header: R?, encryptedKey: Data?)],
    jwk: JWK?,
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?
) -> (header: R?, encryptedKey: Data?)? {
    guard recipients.count == 1 else {
        return recipients.first {
            recipientMatch(
                jwk: jwk,
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: $0.header
            )
        }
    }
    return recipients.first
}

