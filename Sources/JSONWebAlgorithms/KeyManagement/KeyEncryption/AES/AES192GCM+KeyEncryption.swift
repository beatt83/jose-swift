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
import JSONWebKey

/// Extension to make `AES192GCM` conform to `KeyWrapping`.
extension AES192GCM: KeyWrapping {
    
    /// Encrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - cek: The content encryption key to be encrypted.
    ///   - using: The `JWK` to use for encryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key encryption.
    /// - Throws: An error if required arguments are missing or if the encryption fails.
    /// - Returns: A `KeyEncriptionResultMetadata` object containing the encrypted key, initialization vector, authentication tag, and other metadata.
    public func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata {
        guard let key = using.key else {
            throw CryptoError.missingArguments([])
        }

        let initializationVector = try arguments.initializationVector ?? generateInitializationVector()
        let (cipher, authenticationTag) = try AESGCM.encrypt(
            payload: cek,
            cek: key,
            initializationVector: initializationVector
        )

        return .init(
            encryptedKey: cipher,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            pbs2saltInput: nil,
            pbs2saltCount: nil,
            otherMetadata: [:]
        )
    }
}
