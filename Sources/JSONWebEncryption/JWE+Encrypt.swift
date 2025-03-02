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

extension JWE {
    
    /// Initializes a `JWE` object for encryption, given the payload and various encryption parameters.
    ///
    /// This method configures a `JWE` object with specified encryption settings, preparing it for data encryption.
    /// 
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - keyManagementAlg: The key management algorithm to use.
    ///   - encryptionAlgorithm: The content encryption algorithm.
    ///   - senderKey: Optional sender's key for certain key agreement or wrapping algorithms.
    ///   - recipientKey: Optional recipient's key for asymmetric encryption.
    ///   - cek: Optional Content Encryption Key, providing the ability to specify a pre-determined key.
    ///   - initializationVector: Optional initialization vector for algorithms requiring it.
    ///   - additionalAuthenticationData: Optional additional authenticated data for use in certain algorithms.
    ///   - password: Optional password used in key derivation for certain algorithms.
    ///   - saltLength: Optional salt length for key derivation in algorithms like PBES2.
    ///   - iterationCount: Optional iteration count for key derivation in algorithms like PBES2.
    /// - Throws: Errors related to encryption parameter configuration or the encryption process itself.
    public init(
        payload: Data,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm
        )
        
        let parts = try JWE.encryptionModule.encryptor(alg: keyManagementAlg).encrypt(
            payload: payload,
            senderKey: senderKey.map { try prepareJWK(key: $0) },
            recipientKey: recipientKey.map { try prepareJWK(key: $0) },
            protectedHeader: protectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
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
    ///
    /// This method allows for a high level of customization of the `JWE` header parameters and encryption settings.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional protected header, specifying encryption parameters.
    ///   - unprotectedHeader: Optional shared header, specifying additional metadata.
    ///   - senderKey: Optional sender's key for key agreement or wrapping.
    ///   - recipientKey: Optional recipient's key for asymmetric encryption.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - password: Optional password used in key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Throws: Errors related to encryption parameter configuration or the encryption process.
    public init<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
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
        
        let parts = try JWE.encryptionModule.encryptor(alg: alg).encrypt(
            payload: payload,
            senderKey: senderKey.map { try prepareJWK(key: $0) },
            recipientKey: recipientKey.map { try prepareJWK(key: $0) },
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
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
    
    /// Initializes a `JWE` object using specified encryption and key management algorithms, with a custom unprotected header.
    ///
    /// This method is tailored for scenarios requiring a specific combination of encryption and key management algorithms,
    /// while also allowing a custom unprotected header.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - keyManagementAlg: The key management algorithm.
    ///   - encryptionAlgorithm: The content encryption algorithm.
    ///   - unprotectedHeader: Optional shared header for additional metadata.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Throws: Errors related to encryption parameter configuration or the encryption process.
    public init<U: JWERegisteredFieldsHeader>(
        payload: Data,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm
        )
        
        try self.init(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            cek: cek,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object with custom headers and multiple recipients.
    ///
    /// This method allows for a high degree of flexibility by accepting generic header types and a list of recipients.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional custom protected header.
    ///   - unprotectedHeader: Optional custom shared unprotected header.
    ///   - senderKey: Optional sender's key.
    ///   - recipients: An array of tuples, each containing a recipient-specific header and a recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Returns: A `JWEJson<P, U, R>` object representing the serialized JWE.
    /// - Throws: Errors related to encryption parameter configuration or the encryption process.
    public static func jsonSerialization<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipients: [(header: R, key: KeyRepresentable)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWEJson<P, U, R> {
        let recipientParts = try encryptionModule.multiEncryptor.encrypt(
            payload: payload,
            senderKey: senderKey.map { try prepareJWK(key: $0) },
            recipients: try recipients.map { ($0.header, try prepareJWK(key: $0.key)) },
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount,
            encryptionModule: encryptionModule
        )
        
        guard let firstRecipient = recipientParts.first else {
            throw JWE.JWEError.noRecipients
        }
        
        let protectedHeader = firstRecipient.protectedHeader ?? protectedHeader
        
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
    ///
    /// This method allows for specifying a custom shared unprotected header while using default headers for the protected
    /// and recipient-specific headers.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - encryptionAlgorithm: The content encryption algorithm to be used.
    ///   - unprotectedHeader: Optional custom shared unprotected header.
    ///   - senderKey: Optional sender's key.
    ///   - recipients: An array of tuples, each containing a key management algorithm and a recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Returns: A `JWEJson<DefaultJWEHeaderImpl, U, DefaultJWEHeaderImpl>` object representing the serialized JWE.
    /// - Throws: Errors related to encryption parameter configuration or the encryption process.
    public static func jsonSerialization<U: JWERegisteredFieldsHeader>(
        payload: Data,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipients: [(alg: KeyManagementAlgorithm, key: KeyRepresentable)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWEJson<DefaultJWEHeaderImpl, U, DefaultJWEHeaderImpl> {
        let protectedHeader = DefaultJWEHeaderImpl(
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm
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
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object using a specified encryption algorithm and a set of recipients.
    ///
    /// This method is particularly used when you have multiple recipients and a single encryption algorithm.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - encryptionAlgorithm: The content encryption algorithm to be used.
    ///   - senderKey: Optional sender's key.
    ///   - recipients: An array of tuples, each containing a key management algorithm and a recipient's key.
    ///   - cek: Optional Content Encryption Key.
    ///   - initializationVector: Optional initialization vector.
    ///   - additionalAuthenticationData: Optional additional authenticated data.
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Returns: A `JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl>` object representing the serialized JWE.
    /// - Throws: Errors related to encryption
    public static func jsonSerialization(
        payload: Data,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        senderKey: KeyRepresentable? = nil,
        recipients: [(alg: KeyManagementAlgorithm, key: KeyRepresentable)],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl> {
        return try jsonSerialization(
            payload: payload,
            encryptionAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            unprotectedHeader: nil,
            senderKey: senderKey,
            recipients: recipients,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
        )
    }
    
    /// Creates a JSON serialization of a `JWE` object, primarily for cases with multiple recipient keys.
    ///
    /// This method is useful for encrypting data for multiple recipients, each potentially using different encryption keys.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - protectedHeader: Optional protected header. It should conform to `JWERegisteredFieldsHeader`.
    ///   - unprotectedHeader: Optional custom shared unprotected header. It also should conform to `JWERegisteredFieldsHeader`.
    ///   - senderKey: Optional sender's key. Used in scenarios where the sender needs to be authenticated.
    ///   - recipientKeys: Array of recipient keys. Each key will be used to encrypt the data for a specific recipient.
    ///   - cek: Optional Content Encryption Key. If not provided, it will be generated.
    ///   - initializationVector: Optional initialization vector. Used for certain encryption algorithms to provide additional randomness.
    ///   - additionalAuthenticationData: Optional additional authenticated data. This data is authenticated but not encrypted.
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation.
    ///   - iterationCount: Optional iteration count for key derivation.
    /// - Returns: A `JWEJson<P, U, DefaultJWEHeaderImpl>` object representing the serialized JWE.
    /// - Throws: Serialization related errors, typically arising from encryption or encoding failures. Throws `JWE.JWEError.noRecipients` if there are no recipients provided.
    public static func jsonSerialization<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: Data,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKeys: [KeyRepresentable],
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWEJson<P, U, DefaultJWEHeaderImpl> {
        return try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipients: try recipientKeys.map { (DefaultJWEHeaderImpl(from: try prepareJWK(key: $0)), $0)},
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount
        )
    }
}

func prepareJWK(key: KeyRepresentable?) throws -> JWK {
    switch key {
    case let value as JWK:
        return value
    case let value as JWKRepresentable:
        return value.jwkRepresentation
    default:
        throw CryptoError.keyFormatNotSupported(format: String(describing: key.self), supportedFormats: ["JWK", "JWKRepresentable"])
    }
}
