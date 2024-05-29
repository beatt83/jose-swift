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
import JSONWebKey
import secp256k1

/// `Secp256k1KeyGeneration` provides methods to generate random keys, private keys, and key pairs in JWK format for secp256k1.
public struct Secp256k1KeyGeneration: KeyGeneration {

    /// Generates a random key.
    /// - Throws: An error if the random data generation fails.
    /// - Returns: A `Data` object containing the generated random key.
    public func generateRandomKey() throws -> Data {
        return try SecureRandom.secureRandomData(count: 32)
    }

    /// Generates a private key for the specified purpose.
    /// - Parameter purpose: The purpose for which the key is generated (`signing` or `keyAgreement`).
    /// - Throws: An error if the key generation fails.
    /// - Returns: A `Data` object containing the generated private key.
    public func generatePrivateKey(purpose: KeyGenerationPurpose) throws -> Data {
        switch purpose {
        case .signing:
            return try secp256k1.Signing.PrivateKey().dataRepresentation
        case .keyAgreement:
            return try secp256k1.KeyAgreement.PrivateKey().rawRepresentation
        }
    }

    /// Generates a key pair in JWK format for the specified purpose.
    /// - Parameter purpose: The purpose for which the key pair is generated (`signing` or `keyAgreement`).
    /// - Throws: An error if the key generation fails.
    /// - Returns: A `JWK` object containing the generated key pair.
    public func generateKeyPairJWK(purpose: KeyGenerationPurpose) throws -> JWK {
        switch purpose {
        case .signing:
            return try secp256k1.Signing.PrivateKey(format: .uncompressed).jwkRepresentation
        case .keyAgreement:
            return try secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation
        }
    }
}
