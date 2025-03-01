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

/// `AESKeyUnwrap` provides methods to decrypt content encryption keys (CEKs) using AES key unwrapping.
struct AESKeyUnwrap: KeyUnwrapping {
    
    /// Decrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - encryptedKey: The encrypted content encryption key to be decrypted.
    ///   - using: The `JWK` to use for decryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key decryption.
    /// - Throws: An error if the decryption fails or if the required key is missing.
    /// - Returns: The decrypted key as a `Data` object.
    public func contentKeyDecrypt(
        encryptedKey: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> Data {
        guard let key = using.key else {
            throw CryptoError.missingOctetSequenceKey
        }
        
        if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
            return try AES.KeyWrap.unwrap(
                encryptedKey,
                using: .init(data: key)
            ).withUnsafeBytes { Data($0) }
        } else {
            return try AESKeyWrapperCommonCrypto().unwrap(key: encryptedKey, encryptionKey: key)
        }
    }
}
