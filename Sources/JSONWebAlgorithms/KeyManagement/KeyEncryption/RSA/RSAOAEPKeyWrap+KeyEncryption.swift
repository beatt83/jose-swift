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

import CryptoSwift
import Foundation
import JSONWebKey
import Security

/// `RSAOAEPKeyWrapper` provides methods to encrypt content encryption keys (CEKs) using RSAES-OAEP with SHA-1.
public struct RSAOAEPKeyWrapper: KeyWrapping {
    
    /// Generates an initialization vector.
    /// - Throws: An error if the generation fails.
    /// - Returns: An empty `Data` object as no initialization vector is required for RSA key wrapping.
    public func generateInitializationVector() throws -> Data {
        Data()
    }
    
    /// Encrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - cek: The content encryption key to be encrypted.
    ///   - using: The `JWK` to use for encryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key encryption.
    /// - Throws: An error if the encryption fails or if the required components are missing from the JWK.
    /// - Returns: A `KeyEncriptionResultMetadata` object containing the encrypted key and other metadata.
    public func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata {
        guard let n = using.n else {
            throw JWK.Error.missingNComponent
        }
        guard let e = using.e else {
            throw JWK.Error.missingEComponent
        }
        let rsaPublicKey = CryptoSwift.RSA(n: BigUInteger(n), e: BigUInteger(e))
        let derEncodedRSAPublicKey = try rsaPublicKey.publicKeyExternalRepresentation()
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: n.count * 8,
            kSecAttrIsPermanent as String: false,
        ]
        var error: Unmanaged<CFError>?
        guard let rsaSecKey = SecKeyCreateWithData(
            derEncodedRSAPublicKey as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw CryptoError.invalidRSAKey
        }
        let secKeyAlgorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1
        var encryptionError: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            rsaSecKey,
            secKeyAlgorithm,
            cek as CFData,
            &encryptionError
        ) else {
            throw CryptoError.securityLayerError(internalStatus: nil, internalError: encryptionError?.takeRetainedValue())
        }
        return .init(encryptedKey: ciphertext as Data)
    }
}
