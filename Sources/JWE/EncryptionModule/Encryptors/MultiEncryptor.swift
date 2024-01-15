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

struct MultiEncryptor: JWEMultiEncryptor {
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK?,
        recipients: [(header: R?, key: JWK)],
        protectedHeader: P?,
        unprotectedHeader: U?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data?,
        encryptionModule: JWEEncryptionModule = .default
    ) throws -> [JWEParts<P, R>] {
        guard let enc = getEncoding(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: nil
        ) else {
            throw JWE.JWEError.missingContentEncryptionAlgorithm
        }
        
        let cek = try enc.encryptor.generateCEK()
        
        return try recipients.map { recipientHeader, key in
            guard let alg = getKeyAlgorithm(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader
            ) else {
                throw JWE.JWEError.missingKeyAlgorithm
            }
            
            return try encryptionModule.encryptor(alg: alg).encrypt(
                payload: payload,
                senderKey: senderKey,
                recipientKey: key,
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: recipientHeader ?? R.init(from: key),
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData,
                multiRecipients: true
            )
        }
    }
    
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK? = nil,
        recipientsKeys: [JWK],
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = .default
    ) throws -> [JWEParts<P, DefaultJWEHeaderImpl>] {
        try self.encrypt(
            payload: payload,
            senderKey: senderKey,
            recipients: recipientsKeys.map {
                (DefaultJWEHeaderImpl(from: $0), $0)
            },
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
}
