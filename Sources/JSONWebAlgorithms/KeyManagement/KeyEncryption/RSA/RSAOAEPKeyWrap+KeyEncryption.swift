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
import Foundation
import JSONWebKey
import _CryptoExtras

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

        guard let encryptionKey = try? _RSA.Encryption.PublicKey(unsafeDERRepresentation: derEncodedRSAPublicKey) else {
            throw CryptoError.invalidRSAKey
        }
        
        guard let encryptedData = try? Data(encryptionKey.encrypt(cek, padding: _RSA.Encryption.Padding.PKCS1_OAEP)) else {
            throw CryptoError.securityLayerError(internalStatus: nil, internalError: nil)
        }
        return .init(encryptedKey: encryptedData)
    }
}
