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

import Crypto
import Foundation

/// `AES192GCM` provides methods to encrypt and decrypt data using AES-192-GCM.
public struct AES192GCM: ContentEncryptor, ContentDecryptor {
    /// The content encryption algorithm used, represented as a string.
    public let contentEncryptionAlgorithm: String = ContentEncryptionAlgorithm.a192GCM.rawValue
    /// The size of the initialization vector in bits.
    public let initializationVectorSizeInBits: Int = ContentEncryptionAlgorithm.a192GCM.initializationVectorSizeInBits
    /// The size of the content encryption key (CEK) in bits.
    public let cekKeySize: Int = ContentEncryptionAlgorithm.a192GCM.keySizeInBits
    
    /// Generates a random initialization vector.
    /// - Throws: An error if the random data generation fails.
    /// - Returns: A data object containing the initialization vector.
    public func generateInitializationVector() throws -> Data {
        try SecureRandom.secureRandomData(count: initializationVectorSizeInBits / 8)
    }
    
    /// Generates a random content encryption key (CEK).
    /// - Throws: An error if the random data generation fails.
    /// - Returns: A data object containing the CEK.
    public func generateCEK() throws -> Data {
        try SecureRandom.secureRandomData(count: cekKeySize / 8)
    }
    
    /// Encrypts the payload using AES-192-GCM.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - key: The encryption key.
    ///   - arguments: Additional encryption arguments, such as initialization vector and additional authenticated data.
    /// - Throws: An error if the encryption fails.
    /// - Returns: A `ContentEncryptionResult` containing the cipher text and authentication tag.
    public func encrypt(
        payload: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> ContentEncryptionResult {
        let (cipher, tag) = try AESGCM.encrypt(
            payload: payload,
            cek: key,
            initializationVector: arguments.initializationVector ?? generateInitializationVector(),
            additionalAuthenticatedData: arguments.additionalAuthenticationData ?? Data()
        )
        return .init(cipher: cipher, authenticationData: tag)
    }
    
    /// Decrypts the cipher text using AES-192-GCM.
    /// - Parameters:
    ///   - cipher: The data to be decrypted.
    ///   - key: The decryption key.
    ///   - arguments: Additional decryption arguments, such as initialization vector and authentication tag.
    /// - Throws: An error if the decryption fails.
    /// - Returns: The decrypted data.
    public func decrypt(
        cipher: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> Data {
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard let tag = arguments.authenticationTag else {
            throw CryptoError.missingAuthenticationTag
        }
        
        guard let aad = arguments.additionalAuthenticationData else {
            throw CryptoError.missingAdditionalAuthenticatingData
        }
        
        return try AESGCM.decrypt(
            cipher: cipher,
            using: key,
            initializationVector: iv,
            authenticationTag: tag,
            additionalAuthenticatedData: aad
        )
    }
}
