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
import Crypto
import _CryptoExtras


/// `RSAOAEP256KeyUnwrap` provides methods to decrypt content encryption keys (CEKs) using RSAES-OAEP with SHA-256.
public struct RSAOAEP256KeyUnwrap: KeyUnwrapping {
    
    /// Decrypts the content encryption key (CEK) using the provided JWK and key encryption arguments.
    /// - Parameters:
    ///   - encryptedKey: The encrypted content encryption key to be decrypted.
    ///   - using: The `JWK` to use for decryption.
    ///   - arguments: An array of `KeyEncryptionArguments` containing the necessary parameters for key decryption.
    /// - Throws: An error if the decryption fails or if required components are missing from the JWK.
    /// - Returns: The decrypted key as a `Data` object.
    public func contentKeyDecrypt(
        encryptedKey: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> Data {
        guard let n = using.n else {
            throw JWK.Error.missingNComponent
        }
        guard let e = using.e else {
            throw JWK.Error.missingEComponent
        }

        let rsaPrivateKey: CryptoSwift.RSA
        if let p = using.p, let q = using.q, let d = using.d {
            rsaPrivateKey = try CryptoSwift.RSA(
                n: BigUInteger(n),
                e: BigUInteger(e),
                d: BigUInteger(d),
                p: BigUInteger(p),
                q: BigUInteger(q)
            )
        } else {
            rsaPrivateKey = CryptoSwift.RSA(
                n: BigUInteger(n),
                e: BigUInteger(e),
                d: using.d.map { BigUInteger($0) }
            )
        }
        let derEncodedRSAPrivateKey = try rsaPrivateKey.externalRepresentation()
        
        guard let decryptionKey = try? _RSA.Encryption.PrivateKey(derRepresentation: derEncodedRSAPrivateKey) else {
            throw CryptoError.securityLayerError(internalStatus: nil, internalError: nil)
        }
        
        guard let decryptedData = try? Data(decryptionKey.decrypt(encryptedKey, padding: _RSA.Encryption.Padding.PKCS1_OAEP_SHA256)) else {
            throw CryptoError.failedRSAKeyUnwrap

        }
        return decryptedData
    }
}
