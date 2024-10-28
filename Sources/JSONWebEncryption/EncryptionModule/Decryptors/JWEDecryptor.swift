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

/// `JWEDecryptor` protocol defines functionality for decrypting JWE objects.
public protocol JWEDecryptor: Sendable {
    /// Supported key management algorithms by this decryptor.
    var supportedKeyManagementAlgorithms: [KeyManagementAlgorithm] { get }

    /// Supported content encryption algorithms by this decryptor.
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] { get }
    
    /// Decrypts a JWE object given various headers and cryptographic components.
    /// - Parameters:
    ///   - protectedHeader: Protected header, conforming to `JWERegisteredFieldsHeader`.
    ///   - unprotectedHeader: Unprotected header, conforming to `JWERegisteredFieldsHeader`.
    ///   - cipher: Encrypted content data.
    ///   - recipientHeader: Recipient-specific header, conforming to `JWERegisteredFieldsHeader`.
    ///   - encryptedKey: Encrypted content encryption key.
    ///   - initializationVector: Initialization vector for the encryption algorithm.
    ///   - authenticationTag: Authentication tag for verifying the integrity of the decrypted data.
    ///   - additionalAuthenticationData: Additional authenticated data.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - sharedKey: Optional shared key.
    ///   - password: Optional password for key derivation.
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
    func decrypt<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader, R: JWERegisteredFieldsHeader>(
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
        sharedKey: JWK?,
        password: Data?
    ) throws -> Data
}

/// `JWEMultiDecryptor` protocol defines functionality for decrypting JWE objects with multiple recipients.
public protocol JWEMultiDecryptor: Sendable {
    /// Decrypts a JWE object with multiple recipients given various headers and cryptographic components.
    /// - Parameters:
    ///   - protectedHeader: Protected header, conforming to `JWERegisteredFieldsHeader`.
    ///   - unprotectedHeader: Unprotected header, conforming to `JWERegisteredFieldsHeader`.
    ///   - cipher: Encrypted content data.
    ///   - recipients: Array of recipient headers and encrypted keys.
    ///   - initializationVector: Initialization vector for the encryption algorithm.
    ///   - authenticationTag: Authentication tag for verifying the integrity of the decrypted data.
    ///   - senderKey: Optional sender's key.
    ///   - recipientKey: Optional recipient's key.
    ///   - sharedKey: Optional shared key.
    ///   - additionalAuthenticationData: Additional authenticated data.
    ///   - tryAllRecipients: Flag to attempt decryption with all provided recipient keys.
    ///   - password: Optional password for key derivation.
    ///   - encryptionModule: The encryption module to use.
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
    func decrypt<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader, R: JWERegisteredFieldsHeader>(
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
        password: Data?,
        encryptionModule: JWEEncryptionModule
    ) throws -> Data
}

public extension JWEDecryptor {
    
    /// Simplified decryption method allowing optional parameters.
    /// Decrypts a JWE object using default or provided headers, keys, and cryptographic components.
    /// - Parameters:
    ///   - protectedHeader: Protected header (optional).
    ///   - unprotectedHeader: Unprotected header (optional).
    ///   - cipher: Encrypted content data.
    ///   - recipientHeader: Recipient-specific header (optional).
    ///   - encryptedKey: Encrypted content encryption key (optional).
    ///   - initializationVector: Initialization vector (optional).
    ///   - authenticationTag: Authentication tag (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - senderKey: Sender's key (optional).
    ///   - recipientKey: Recipient's key (optional).
    ///   - sharedKey: Shared key (optional).
    ///   - password: Password for key derivation (optional).
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
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
        sharedKey: JWK? = nil,
        password: Data? = nil
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
            sharedKey: sharedKey,
            password: password
        )
    }
    
    /// Decryption method that decodes protected and unprotected headers from encoded data.
    /// - Parameters:
    ///   - encodedProtectedHeader: Base64URL encoded protected header data (optional).
    ///   - encodedUnprotectedHeaderData: Base64URL encoded unprotected header data (optional).
    ///   - cipher: Encrypted content data.
    ///   - recipientHeader: Recipient-specific header (optional).
    ///   - encryptedKey: Encrypted content encryption key (optional).
    ///   - initializationVector: Initialization vector (optional).
    ///   - authenticationTag: Authentication tag (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - senderKey: Sender's key (optional).
    ///   - recipientKey: Recipient's key (optional).
    ///   - sharedKey: Shared key (optional).
    ///   - password: Password for key derivation (optional).
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
    func decrypt<
        R: JWERegisteredFieldsHeader
    >(
        encodedProtectedHeader: Data? = nil,
        encodedUnprotectedHeaderData: Data? = nil,
        cipher: Data,
        recipientHeader: R? = nil as DefaultJWEHeaderImpl?,
        encryptedKey: Data? = nil,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        password: Data? = nil
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
            sharedKey: sharedKey,
            password: password
        )
    }
}

public extension JWEMultiDecryptor {
    
    /// Simplified decryption method for multiple recipients allowing optional parameters.
    /// Decrypts a JWE object for multiple recipients using default or provided headers, keys, and cryptographic components.
    /// - Parameters:
    ///   - protectedHeader: Protected header (optional).
    ///   - unprotectedHeader: Unprotected header (optional).
    ///   - cipher: Encrypted content data.
    ///   - recipients: Array of recipient headers and encrypted keys.
    ///   - initializationVector: Initialization vector (optional).
    ///   - authenticationTag: Authentication tag (optional).
    ///   - senderKey: Sender's key (optional).
    ///   - recipientKey: Recipient's key (optional).
    ///   - sharedKey: Shared key (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - tryAllRecipients: Flag to attempt decryption with all provided recipient keys (optional).
    ///   - password: Password for key derivation (optional).
    ///   - encryptionModule: Encryption module (optional).
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
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
        password: Data? = nil,
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
            password: password,
            encryptionModule: encryptionModule
        )
    }
    
    /// Decryption method for multiple recipients that decodes protected and unprotected headers from encoded data.
    /// - Parameters:
    ///   - encodedProtectedHeader: Base64URL encoded protected header data (optional).
    ///   - encodedUnprotectedHeaderData: Base64URL encoded unprotected header data (optional).
    ///   - cipher: Encrypted content data.
    ///   - recipients: Array of recipient headers and encrypted keys.
    ///   - initializationVector: Initialization vector (optional).
    ///   - authenticationTag: Authentication tag (optional).
    ///   - senderKey: Sender's key (optional).
    ///   - recipientKey: Recipient's key (optional).
    ///   - sharedKey: Shared key (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - tryAllRecipients: Flag to attempt decryption with all provided recipient keys (optional).
    ///   - password: Password for key derivation (optional).
    ///   - encryptionModule: Encryption module (optional).
    /// - Returns: Decrypted data as `Data`.
    /// - Throws: Encryption related errors.
    func decrypt<
        R: JWERegisteredFieldsHeader
    >(
        encodedProtectedHeader: Data? = nil,
        encodedUnprotectedHeaderData: Data? = nil,
        cipher: Data,
        recipients: [(header: R?, encryptedKey: Data?)],
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        additionalAuthenticationData: Data?,
        tryAllRecipients: Bool = false,
        password: Data? = nil,
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
            password: password,
            encryptionModule: encryptionModule
        )
    }
}
