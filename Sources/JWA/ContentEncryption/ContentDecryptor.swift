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

/// `ContentDecryptor` is a protocol that defines functionality for decrypting data.
public protocol ContentDecryptor {
    /// Decrypts the given cipher data using the specified key and additional arguments.
    /// - Parameters:
    ///   - cipher: The encrypted data (cipher) to be decrypted.
    ///   - key: The key used for the decryption process.
    ///   - arguments: An array of `ContentEncryptionArguments` providing additional information required for decryption.
    /// - Returns: The decrypted data.
    /// - Throws: An error if decryption fails. This could be due to incorrect keys, corrupted data, or incompatible arguments.
    func decrypt(
        cipher: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> Data
}
