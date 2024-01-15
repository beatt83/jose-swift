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

/// `KeyGenerationPurpose` is an enumeration representing the intended purpose of a generated key.
public enum KeyGenerationPurpose {
    /// Key generation for signing purposes.
    /// Indicates that the generated key will be used for signing data to ensure its integrity and authenticity.
    case signing

    /// Key generation for key agreement purposes.
    /// Indicates that the generated key will be used in cryptographic key agreement protocols to securely exchange keys.
    case keyAgreement
}

/// `KeyGeneration` is a protocol that defines functionality for generating cryptographic keys.
public protocol KeyGeneration {
    /// Generates a random key suitable for cryptographic operations.
    /// - Returns: A random key as `Data`.
    /// - Throws: An error if the key generation process fails.
    func generateRandomKey() throws -> Data

    /// Generates a private key for a specified purpose.
    /// - Parameter purpose: The purpose for which the key is being generated, either signing or key agreement.
    /// - Returns: A private key as `Data`.
    /// - Throws: An error if the key generation process fails.
    func generatePrivateKey(purpose: KeyGenerationPurpose) throws -> Data

    /// Generates a key pair in JSON Web Key (JWK) format for a specified purpose.
    /// - Parameter purpose: The purpose for which the key pair is being generated.
    /// - Returns: A `JWK` object representing the key pair.
    /// - Throws: An error if the key pair generation process fails.
    func generateKeyPairJWK(purpose: KeyGenerationPurpose) throws -> JWK
}
