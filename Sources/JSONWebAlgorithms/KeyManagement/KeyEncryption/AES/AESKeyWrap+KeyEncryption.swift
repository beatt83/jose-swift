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
import Tools

/// `AESKeyWrap` provides methods to encrypt content encryption keys (CEKs) using AES key wrapping.
struct AESKeyWrap: KeyWrapping {
    
    /// Generates an initialization vector.
    /// - Throws: An error if the generation fails.
    /// - Returns: An empty `Data` object as no initialization vector is required for AES key wrapping.
    public func generateInitializationVector() throws -> Data {
        Data()
    }
    
    /// Encrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - cek: The content encryption key to be encrypted.
    ///   - using: The `JWK` to use for encryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key encryption.
    /// - Throws: An error if the encryption fails or if the required key is missing.
    /// - Returns: A `KeyEncriptionResultMetadata` object containing the encrypted key and other metadata.
    public func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata {
        guard let key = using.key else {
            throw CryptoError.notValidPrivateKey
        }
        
        let encryptedKey = try AES.KeyWrap.wrap(
                .init(data: cek),
                using: .init(data: key)
            )

        return .init(
            encryptedKey: encryptedKey,
            initializationVector: nil,
            authenticationTag: nil,
            pbs2saltInput: nil,
            pbs2saltCount: nil,
            otherMetadata: [:]
        )
    }
}
