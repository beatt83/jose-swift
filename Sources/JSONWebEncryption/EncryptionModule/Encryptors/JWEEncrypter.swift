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

public protocol JWEEncryptor {
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] { get }
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] { get }
    
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
        hasMultiRecipients: Bool
    ) throws -> JWEParts<P, R>
}

public protocol JWEMultiEncryptor {
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
        encryptionModule: JWEEncryptionModule
    ) throws -> [JWEParts<P, R>]
}

extension JWEEncryptor {
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        recipientHeader: R? = nil as DefaultJWEHeaderImpl?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        multiRecipients: Bool = false
    ) throws -> JWEParts<P, R> {
        try self.encrypt(
            payload: payload,
            senderKey: senderKey,
            recipientKey: recipientKey,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            hasMultiRecipients: multiRecipients
        )
    }
}

extension JWEMultiEncryptor {
    public func encrypt<
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
            additionalAuthenticationData: additionalAuthenticationData,
            encryptionModule: encryptionModule
        )
    }
}
