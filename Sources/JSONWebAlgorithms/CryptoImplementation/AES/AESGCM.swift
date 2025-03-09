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
import Tools

/// `AESGCM` provides methods to encrypt and decrypt data using AES-GCM (Galois/Counter Mode).
public struct AESGCM {
    
    /// Encrypts the payload using AES-GCM.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - cek: The content encryption key.
    ///   - initializationVector: The initialization vector (default is empty data).
    ///   - additionalAuthenticatedData: Additional data to be authenticated (default is empty data).
    /// - Throws: An error if the encryption fails.
    /// - Returns: A tuple containing the cipher text and authentication tag.
    public static func encrypt(
        payload: Data,
        cek: Data,
        initializationVector: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> (cipher: Data, authenticationData: Data) {
        let sealedBox = try AES.GCM.seal(
            payload,
            using: .init(data: cek),
            nonce: .init(data: initializationVector),
            authenticating: additionalAuthenticatedData
        )
        return (sealedBox.ciphertext, sealedBox.tag)
    }
    
    /// Decrypts the cipher text using AES-GCM.
    /// - Parameters:
    ///   - cipher: The data to be decrypted.
    ///   - using: The decryption key.
    ///   - initializationVector: The initialization vector (default is empty data).
    ///   - authenticationTag: The authentication tag (default is empty data).
    ///   - additionalAuthenticatedData: Additional data to be authenticated (default is empty data).
    /// - Throws: An error if the decryption fails.
    /// - Returns: The decrypted data.
    public static func decrypt(
        cipher: Data,
        using: Data,
        initializationVector: Data = Data(),
        authenticationTag: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> Data {
        return try AES.GCM.open(
            .init(
                nonce: .init(data: initializationVector),
                ciphertext: cipher,
                tag: authenticationTag
            ),
            using: .init(data: using),
            authenticating: additionalAuthenticatedData
        )
    }
}
