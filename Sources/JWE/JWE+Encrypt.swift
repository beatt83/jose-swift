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

extension JWE {
    
    /// Initializes a `JWE` object for encryption, given the payload and various encryption parameters.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - keyManagementAlg: The key management algorithm to use.
    ///   - encryptionAlgorithm: The content encryption algorithm.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Throws: Encryption related errors.
    public init(
        payload: Data,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: nil
        )
        
        let parts = try encryptionModule.encryptor(alg: keyManagementAlg).encrypt(
            payload: payload,
            senderKey: senderKey,
            recipientKey: recipientKey,
            protectedHeader: protectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
        let finalProtectedHeader = parts.protectedHeader ?? protectedHeader
        self.protectedHeader = finalProtectedHeader
        self.protectedHeaderData = try JSONEncoder.jose.encode(finalProtectedHeader)
        self.unprotectedHeader = nil
        self.unprotectedHeaderData = nil
        self.initializationVector = parts.initializationVector
        self.additionalAuthenticatedData = parts.additionalAuthenticationData
        self.authenticationTag = parts.authenticationTag
        self.cipher = parts.cipherText
        self.encryptedKey = parts.encryptedKey
    }
    
    /// Initializes a `JWE` object with specified protected and shared headers.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional protected header.
    ///   - unprotectedHeader: Optional shared header.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Throws: Encryption related errors.
    public init<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws {
        guard
            let alg = getKeyAlgorithm(
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                recipientHeader: nil
            )
        else {
            throw JWE.JWEError.missingKeyAlgorithm
        }
        
        let parts = try encryptionModule.encryptor(alg: alg).encrypt(
            payload: payload,
            senderKey: senderKey,
            recipientKey: recipientKey,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
        
        let finalProtectedHeader = parts.protectedHeader.map { P.init(from: $0) }
        ?? protectedHeader
        ?? P.init()
        
        self.protectedHeader = finalProtectedHeader
        self.protectedHeaderData = try JSONEncoder.jose.encode(finalProtectedHeader)
        self.unprotectedHeader = unprotectedHeader
        self.unprotectedHeaderData = try unprotectedHeader.map { try JSONEncoder.jose.encode($0) }
        self.initializationVector = parts.initializationVector
        self.additionalAuthenticatedData = parts.additionalAuthenticationData
        self.authenticationTag = parts.authenticationTag
        self.cipher = parts.cipherText
        self.encryptedKey = parts.encryptedKey
    }
    
    /// Initializes a `JWE` object with specified protected and shared headers.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - keyManagementAlg: The key encryption algorithm to be used.
    ///   - encryptionAlgorithm: The content encryption algorithm to be used.
    ///   - unprotectedHeader: Optional shared header.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Throws: Encryption related errors.
    public init<U: JWERegisteredFieldsHeader>(
        payload: Data,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        cek: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm
        )
        
        try self.init(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            cek: cek,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object with custom headers and multiple recipients.
    /// This method allows for a high degree of flexibility by accepting generic header types and a list of recipients.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional custom protected header. It should conform to `JWERegisteredFieldsHeader`.
    ///   - unprotectedHeader: Optional custom shared unprotected header. It also should conform to `JWERegisteredFieldsHeader`.
    ///   - senderKey: Optional sender's key. Used in scenarios where the sender needs to be authenticated.
    ///   - recipients: An array of tuples, each containing a recipient-specific header and a recipient's key.
    ///   - cek: Optional Content Encryption Key. If not provided, it will be generated.
    ///   - initializationVector: Optional initialization vector. Used for certain encryption algorithms to provide additional randomness.
    ///   - additionalAuthenticationData: Optional additional authenticated data. This data is authenticated but not encrypted.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module. Allows for custom encryption processes.
    /// - Returns: A `JWEJson<P, U, R>` object representing the serialized JWE. The type parameters `P`, `U`, and `R` represent the types of the protected, unprotected, and recipient-specific headers, respectively.
    /// - Throws: Serialization related errors, typically arising from encryption or encoding failures. Throws `JWE.JWEError.noRecipients` if there are no recipients provided.
    public static func jsonSerialization<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK? = nil,
        recipients: [(header: R, key: JWK)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> JWEJson<P, U, R> {
        let recipientParts = try encryptionModule.multiEncryptor.encrypt(
            payload: payload,
            senderKey: senderKey,
            recipients: recipients.map { ($0.header, $0.key) },
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData, 
            encryptionModule: encryptionModule
        )
        
        guard let firstRecipient = recipientParts.first else {
            throw JWE.JWEError.noRecipients
        }
        
        return JWEJson(
            protected: protectedHeader,
            protectedData: try JSONEncoder.jose.encode(protectedHeader),
            sharedProtected: unprotectedHeader,
            sharedProtectedData: try JSONEncoder.jose.encode(unprotectedHeader),
            recipients: try recipientParts.map {
                try .init(header: $0.recipientHeader, encryptedKey: $0.encryptedKey)
            },
            cipherText: firstRecipient.cipherText,
            addtionalAuthenticatedData: additionalAuthenticationData,
            initializationVector: firstRecipient.initializationVector,
            authenticationTag: firstRecipient.authenticationTag
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object using a specified encryption algorithm and a set of recipients,
    /// with a custom unprotected header.
    /// This method allows for specifying a custom shared unprotected header while using default headers for the protected
    /// and recipient-specific headers.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - encryptionAlgorithm: The content encryption algorithm to be used.
    ///   - unprotectedHeader: Optional custom shared unprotected header, conforming to `JWERegisteredFieldsHeader`.
    ///   - senderKey: Optional sender's key. Used in scenarios where the sender needs to be authenticated.
    ///   - recipients: An array of tuples, each containing a key management algorithm and a recipient's key.
    ///   - cek: Optional Content Encryption Key. If not provided, it will be generated.
    ///   - initializationVector: Optional initialization vector. Used for certain encryption algorithms to provide additional randomness.
    ///   - additionalAuthenticationData: Optional additional authenticated data. This data is authenticated but not encrypted.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module. Allows for custom encryption processes.
    /// - Returns: A `JWEJson<DefaultJWEHeaderImpl, U, DefaultJWEHeaderImpl>` object representing the serialized JWE.
    ///   The type parameter `U` represents the type of the custom unprotected header.
    /// - Throws: Serialization related errors, typically arising from encryption or encoding failures.
    public static func jsonSerialization<U: JWERegisteredFieldsHeader>(
        payload: Data,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK? = nil,
        recipients: [(alg: KeyManagementAlgorithm, key: JWK)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> JWEJson<DefaultJWEHeaderImpl, U, DefaultJWEHeaderImpl> {
        let protectedHeader = DefaultJWEHeaderImpl(
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: nil
        )
        
        return try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipients: recipients.map {
                (DefaultJWEHeaderImpl(keyManagementAlgorithm: $0.alg), $0.key)
            },
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object using a specified encryption algorithm and a set of recipients.
    /// This method is particularly used when you have multiple recipients and a single encryption algorithm.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - encryptionAlgorithm: The content encryption algorithm to be used.
    ///   - senderKey: Optional sender's key. Used in scenarios where the sender needs to be authenticated.
    ///   - recipients: An array of tuples, each containing a key management algorithm and a recipient's key.
    ///   - cek: Optional Content Encryption Key. If not provided, it will be generated.
    ///   - initializationVector: Optional initialization vector. Used for certain encryption algorithms to provide additional randomness.
    ///   - additionalAuthenticationData: Optional additional authenticated data. This data is authenticated but not encrypted.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module. Allows for custom encryption processes.
    /// - Returns: A `JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl>` object representing the serialized JWE.
    /// - Throws: Serialization related errors, typically arising from encryption or encoding failures.
    public static func jsonSerialization(
        payload: Data,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        senderKey: JWK? = nil,
        recipients: [(alg: KeyManagementAlgorithm, key: JWK)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl> {
        return try jsonSerialization(
            payload: payload,
            encryptionAlgorithm: encryptionAlgorithm,
            unprotectedHeader: nil,
            senderKey: senderKey,
            recipients: recipients,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object, primarily for cases with multiple recipient keys.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional protected header.
    ///   - unprotectedHeader: Optional shared header.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKeys: Array of recipient keys.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Returns: A `JWEJson` object representing the JWE.
    /// - Throws: Serialization related errors.
    public static func jsonSerialization<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK? = nil,
        recipientKeys: [JWK],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> JWEJson<P, U, DefaultJWEHeaderImpl> {
        return try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipients: recipientKeys.map { (DefaultJWEHeaderImpl(from: $0), $0)},
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            encryptionModule: encryptionModule
        )
    }
}
