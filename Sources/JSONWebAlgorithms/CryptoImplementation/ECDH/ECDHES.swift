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

/// `ECDHES` provides methods to process a shared key using ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static).
public struct ECDHES {
    
    /// Processes a shared key using the given private and public keys.
    /// - Parameters:
    ///   - privateKey: The private key as a JWK.
    ///   - publicKey: The public key as a JWK.
    /// - Throws: An error if the key agreement fails or if the private key is not valid.
    /// - Returns: The shared secret as a `Data` object.
    public func processSharedKey(
        privateKey: JWK,
        publicKey: JWK
    ) throws -> Data {
        guard
            let privateKeyAgreement = privateKey.keyAgreement
        else {
            throw CryptoError.notValidPrivateKey
        }

        return try privateKeyAgreement
            .sharedSecretFromKeyAgreement(publicKeyShare: publicKey)
    }
}
