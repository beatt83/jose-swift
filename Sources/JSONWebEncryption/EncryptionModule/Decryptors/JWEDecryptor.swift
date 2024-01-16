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

public protocol JWEDecryptor {
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] { get }
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] { get }
    
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
    ) throws -> Data
}

public protocol JWEMultiDecryptor {
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
        sharedKey: JWK?,
        additionalAuthenticationData: Data?,
        tryAllRecipients: Bool,
        encryptionModule: JWEEncryptionModule
    ) throws -> Data
}

extension JWEDecryptor {
    func decrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        cipher: Data,
        recipientHeader: R? = nil as DefaultJWEHeaderImpl?,
        encryptedKey: Data? = nil,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil
    ) throws -> Data {
        try self.decrypt(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cipher: cipher,
            recipientHeader: recipientHeader,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticationData: additionalAuthenticationData,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey
        )
    }
    
    func decrypt<
        R: JWERegisteredFieldsHeader
    >(
        encodedProtectedHeader: Data?,
        encodedUnprotectedHeaderData: Data?,
        cipher: Data,
        recipientHeader: R? = nil as DefaultJWEHeaderImpl?,
        encryptedKey: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        additionalAuthenticationData: Data?,
        senderKey: JWK?,
        recipientKey: JWK?,
        sharedKey: JWK?
    ) throws -> Data {
        let aad = try AAD.computeAAD(header: encodedProtectedHeader, aad: additionalAuthenticationData)
        
        return try self.decrypt(
            protectedHeader: encodedProtectedHeader
                .map { try JSONDecoder().decode(DefaultJWEHeaderImpl.self, from: $0) },
            unprotectedHeader: encodedUnprotectedHeaderData
                .map { try JSONDecoder().decode(DefaultJWEHeaderImpl.self, from: $0) },
            cipher: cipher,
            recipientHeader: recipientHeader,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticationData: aad,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey
        )
    }
}

extension JWEMultiDecryptor {
    func decrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        cipher: Data,
        recipients: [(header: R?, encryptedKey: Data?)],
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        additionalAuthenticationData: Data? = nil,
        tryAllRecipients: Bool = false,
        encryptionModule: JWEEncryptionModule = .default
    ) throws -> Data {
        try self.decrypt(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cipher: cipher,
            recipients: recipients,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            additionalAuthenticationData: additionalAuthenticationData,
            tryAllRecipients: tryAllRecipients,
            encryptionModule: encryptionModule
        )
    }
    
    func decrypt<
        R: JWERegisteredFieldsHeader
    >(
        encodedProtectedHeader: Data?,
        encodedUnprotectedHeaderData: Data?,
        cipher: Data,
        recipients: [(header: R?, encryptedKey: Data?)],
        initializationVector: Data?,
        authenticationTag: Data?,
        senderKey: JWK?,
        recipientKey: JWK?,
        sharedKey: JWK?,
        additionalAuthenticationData: Data?,
        tryAllRecipients: Bool = false,
        encryptionModule: JWEEncryptionModule = .default
    ) throws -> Data {
        let aad = try AAD.computeAAD(header: encodedProtectedHeader, aad: additionalAuthenticationData)
        return try self.decrypt(
            protectedHeader: encodedProtectedHeader
                .map { try JSONDecoder().decode(DefaultJWEHeaderImpl.self, from: $0) },
            unprotectedHeader: encodedUnprotectedHeaderData
                .map { try JSONDecoder().decode(DefaultJWEHeaderImpl.self, from: $0) },
            cipher: cipher,
            recipients: recipients,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            additionalAuthenticationData: aad,
            tryAllRecipients: tryAllRecipients,
            encryptionModule: encryptionModule
        )
    }
}
