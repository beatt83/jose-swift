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
import JWK

/// `ContentEncryptionArguments` is an enumeration defining additional arguments that can be used in content encryption processes.
public enum ContentEncryptionArguments {
    /// Specifies the key size in bits.
    case keySizeInBits(Int)

    /// Specifies the initialization vector as a `Data` object.
    case initializationVector(Data)

    /// Specifies additional authentication data as a `Data` object.
    case additionalAuthenticationData(Data)

    /// Specifies the authentication tag as a `Data` object.
    case authenticationTag(Data)

    /// Allows for custom data to be included, identified by a key.
    case customData(key: String, value: Data)

    /// Allows for a custom JSON Web Key (JWK) to be included, identified by a key.
    case customJWK(key: String, value: JWK)
}

/// `ContentEncryptionResult` is a struct representing the result of an encryption operation.
public struct ContentEncryptionResult {
    /// The encrypted data (cipher).
    public let cipher: Data

    /// The authentication data associated with the encryption, used for validating the integrity and authenticity of the data.
    public let authenticationData: Data
}

/// `ContentEncryptor` is a protocol defining the functionality for encrypting content.
public protocol ContentEncryptor {
    /// Generates an initialization vector for the encryption process.
    /// - Returns: The generated initialization vector as `Data`.
    /// - Throws: An error if the generation fails.
    func generateInitializationVector() throws -> Data

    /// Generates a Content Encryption Key (CEK) for the encryption process.
    /// - Returns: The generated CEK as `Data`.
    /// - Throws: An error if the generation fails.
    func generateCEK() throws -> Data
    
    /// Encrypts the provided payload using the specified key and additional arguments.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - key: The key used for the encryption process.
    ///   - arguments: An array of `ContentEncryptionArguments` providing additional information required for encryption.
    /// - Returns: A `ContentEncryptionResult` containing the cipher and associated authentication data.
    /// - Throws: An error if encryption fails. This could be due to invalid keys, incompatible arguments, or other issues.
    func encrypt(
        payload: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> ContentEncryptionResult
}

extension Array where Element == ContentEncryptionArguments {
    var keySizeInBits: Int? {
        return self.compactMap {
            if case .keySizeInBits(let int) = $0 {
                return int
            }
            return nil
        }.first
    }

    var initializationVector: Data? {
        return self.compactMap {
            if case .initializationVector(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var additionalAuthenticationData: Data? {
        return self.compactMap {
            if case .additionalAuthenticationData(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
    
    var authenticationTag: Data? {
        return self.compactMap {
            if case .authenticationTag(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
}
