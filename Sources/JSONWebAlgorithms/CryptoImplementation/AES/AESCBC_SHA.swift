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

@preconcurrency import CryptoSwift
import Crypto
import Foundation
import JSONWebKey
import Tools

/// `AESCBC_SHA` provides methods to encrypt and decrypt data using AES-CBC with an HMAC for authentication.
public struct AESCBC_SHA<H: HashFunction> {
    
    /// Encrypts the payload using AES-CBC with an HMAC for authentication.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - cek: The content encryption key.
    ///   - authenticationTagLength: The length of the authentication tag.
    ///   - initializationVector: The initialization vector (default is empty data).
    ///   - additionalAuthenticatedData: Additional data to be authenticated (default is empty data).
    /// - Throws: An error if the encryption fails.
    /// - Returns: A tuple containing the cipher text and authentication tag.
    public static func encrypt(
        payload: Data,
        cek: Data,
        authenticationTagLength: Int,
        initializationVector: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> (cipher: Data, authenticationData: Data) {
        // See https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1
        let contentEncryptionKeyHalfLength = cek.count / 2
        let macKey = cek.prefix(contentEncryptionKeyHalfLength)
        let encKey = cek.suffix(contentEncryptionKeyHalfLength)

        let ciphertext = try AES(
            key: encKey.bytes,
            blockMode: CBC(iv: initializationVector.bytes),
            padding: .pkcs7
        ).encrypt(Array(payload))

        let addLength = UInt64(additionalAuthenticatedData.count * 8).bigEndian.dataRepresentation
        let dataToAuthenticate = additionalAuthenticatedData + initializationVector + ciphertext + addLength
        
        let authenticationTag = CryptoKit.HMAC<H>
            .authenticationCode(
                for: dataToAuthenticate,
                using: .init(data: macKey)
            )
            .withUnsafeBytes { Data($0) }
            .prefix(authenticationTagLength)
        
        return (Data(ciphertext), authenticationTag)
    }
    
    /// Decrypts the cipher text using AES-CBC with an HMAC for authentication.
    /// - Parameters:
    ///   - cipher: The data to be decrypted.
    ///   - cek: The content encryption key.
    ///   - authenticationTagLength: The length of the authentication tag.
    ///   - initializationVector: The initialization vector.
    ///   - additionalAuthenticatedData: Additional data to be authenticated.
    ///   - authenticationTag: The authentication tag.
    /// - Throws: An error if the decryption fails or if the authentication tag doesn't match.
    /// - Returns: The decrypted data.
    public static func decrypt(
        cipher: Data,
        cek: Data,
        authenticationTagLength: Int,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        let contentEncryptionKeyHalfLength = cek.count / 2
        let macKey = cek.prefix(contentEncryptionKeyHalfLength)
        let encKey = cek.suffix(contentEncryptionKeyHalfLength)
        
        let addLength = UInt64(additionalAuthenticatedData.count * 8).bigEndian.dataRepresentation
        let dataToAuthenticate = additionalAuthenticatedData + initializationVector + cipher + addLength
        
        let computedTag = CryptoKit.HMAC<H>
            .authenticationCode(
                for: dataToAuthenticate,
                using: .init(data: macKey)
            )
            .withUnsafeBytes { Data($0) }
            .prefix(authenticationTagLength)

        guard authenticationTag == computedTag else {
            throw CryptoError.decryptionFailedAuthenticationTagDoesntMatch
        }
        
        return Data(try AES(
            key: encKey.bytes,
            blockMode: CBC(iv: initializationVector.bytes),
            padding: .pkcs7
        ).decrypt(Array(cipher)))
    }
}
