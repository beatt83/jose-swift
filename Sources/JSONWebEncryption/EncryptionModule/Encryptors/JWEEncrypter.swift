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

/// JWEEncryptor protocol defines the encryption process for JWE.
public protocol JWEEncryptor: Sendable {
    /// Supported key management algorithms.
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] { get }

    /// Supported content encryption algorithms.
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] { get }
    
    /// Encrypts a payload for JWE.
    /// - Parameters:
    ///   - payload: Data to be encrypted.
    ///   - senderKey: Sender's JWK (optional).
    ///   - recipientKey: Recipient's JWK (optional).
    ///   - protectedHeader: Protected header (optional).
    ///   - unprotectedHeader: Unprotected header (optional).
    ///   - recipientHeader: Recipient-specific header (optional).
    ///   - cek: Content Encryption Key (optional).
    ///   - initializationVector: Initialization vector (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - password: Password for key derivation (optional).
    ///   - saltLength: Salt length for PBES2 (optional).
    ///   - iterationCount: Iteration count for PBES2 (optional).
    ///   - hasMultiRecipients: Flag indicating multiple recipients (affects AAD computation).
    /// - Returns: JWEParts containing the components of the encrypted JWE.
    /// - Throws: Encryption related errors.
    func encrypt<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader, R: JWERegisteredFieldsHeader>(
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
    ) throws -> JWEParts<P, R>
}

/// JWEMultiEncryptor protocol defines the encryption process for JWE with multiple recipients.
public protocol JWEMultiEncryptor: Sendable {
    /// Encrypts a payload for multiple recipients.
    /// - Parameters:
    ///   - payload: Data to be encrypted.
    ///   - senderKey: Sender's JWK (optional).
    ///   - recipients: Array of tuples containing recipient-specific headers and keys.
    ///   - protectedHeader: Protected header (optional).
    ///   - unprotectedHeader: Unprotected header (optional).
    ///   - cek: Content Encryption Key (optional).
    ///   - initializationVector: Initialization vector (optional).
    ///   - additionalAuthenticationData: Additional authenticated data (optional).
    ///   - password: Password for key derivation (optional).
    ///   - saltLength: Salt length for PBES2 (optional).
    ///   - iterationCount: Iteration count for PBES2 (optional).
    ///   - encryptionModule: Encryption module to be used.
    /// - Returns: Array of JWEParts for each recipient.
    /// - Throws: Encryption related errors.
    func encrypt<P: JWERegisteredFieldsHeader, U: JWERegisteredFieldsHeader, R: JWERegisteredFieldsHeader>(
        payload: Data,
        senderKey: JWK?,
        recipients: [(header: R?, key: JWK)],
        protectedHeader: P?,
        unprotectedHeader: U?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data?,
        password: Data?,
        saltLength: Int?,
        iterationCount: Int?,
        encryptionModule: JWEEncryptionModule
    ) throws -> [JWEParts<P, R>]
}

extension JWEEncryptor {
    
    /// Encrypts a payload with optional parameters for flexibility.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - senderKey: Optional sender's JSON Web Key (JWK).
    ///   - recipientKey: Optional recipient's JWK.
    ///   - protectedHeader: Optional protected header.
    ///   - unprotectedHeader: Optional unprotected header.
    ///   - recipientHeader: Optional recipient-specific header.
    ///   - cek: Optional Content Encryption Key (CEK).
    ///   - initializationVector: Optional Initialization Vector (IV).
    ///   - additionalAuthenticationData: Optional Additional Authenticated Data (AAD).
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation algorithms.
    ///   - iterationCount: Optional iteration count for key derivation algorithms.
    ///   - multiRecipients: Indicates whether the JWE has multiple recipients.
    /// - Returns: JWEParts containing the components of the encrypted JWE.
    /// - Throws: Encryption errors.
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
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil,
        ephemeralKey: JWK? = nil,
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
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount,
            ephemeralKey: ephemeralKey,
            hasMultiRecipients: multiRecipients
        )
    }
}

extension JWEMultiEncryptor {
    /// Encrypts a payload for multiple recipients with optional parameters.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - senderKey: Optional sender's JSON Web Key (JWK).
    ///   - recipientsKeys: Array of recipient's JWKs.
    ///   - protectedHeader: Optional protected header.
    ///   - unprotectedHeader: Optional unprotected header.
    ///   - cek: Optional Content Encryption Key (CEK).
    ///   - initializationVector: Optional Initialization Vector (IV).
    ///   - additionalAuthenticationData: Optional Additional Authenticated Data (AAD).
    ///   - password: Optional password for key derivation.
    ///   - saltLength: Optional salt length for key derivation algorithms.
    ///   - iterationCount: Optional iteration count for key derivation algorithms.
    ///   - encryptionModule: The encryption module to be used.
    /// - Returns: An array of JWEParts for each recipient.
    /// - Throws: Encryption errors.
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
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil,
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
            password: password,
            saltLength: saltLength,
            iterationCount: iterationCount,
            encryptionModule: encryptionModule
        )
    }
}
