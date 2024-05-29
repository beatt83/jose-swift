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

import CryptoKit
import Foundation
import JSONWebKey

/// Extension to make `AESGCM` conform to `KeyUnwrapping`.
extension AESGCM: KeyUnwrapping {
    
    /// Decrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - encryptedKey: The encrypted content encryption key to be decrypted.
    ///   - using: The `JWK` to use for decryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key decryption.
    /// - Throws: An error if required arguments are missing or if the decryption fails.
    /// - Returns: The decrypted key as a `Data` object.
    public func contentKeyDecrypt(
        encryptedKey: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> Data {
        guard let key = using.key else {
            throw CryptoError.missingOctetSequenceKey
        }
        
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard let tag = arguments.authenticationTag else {
            throw CryptoError.missingAuthenticationTag
        }
        
        return try AESGCM.decrypt(
            cipher: encryptedKey,
            using: key,
            initializationVector: iv,
            authenticationTag: tag
        )
    }
}
