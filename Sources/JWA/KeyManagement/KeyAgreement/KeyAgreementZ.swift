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

/// `KeyAgreementZ` is a protocol defining functionality for a key agreement mechanism to compute a shared secret, denoted as 'Z'.
public protocol KeyAgreementZ {
    /// Computes a shared secret 'Z' using the provided private key, public key, and optionally an ephemeral key.
    /// - Parameters:
    ///   - privateKey: A `JWK` instance representing the private key of the initiating party.
    ///   - publicKey: A `JWK` instance representing the public key of the responding party.
    ///   - ephemeralKey: An optional `JWK` instance representing an ephemeral key used in the agreement process.
    ///                  Ephemeral keys are temporary and typically used for a single session or transaction.
    ///   - sender: A Boolean value indicating whether the calling party is the sender or receiver in the key agreement process.
    ///            This information can influence how the shared secret is computed in certain protocols.
    /// - Returns: The computed shared secret as `Data`.
    /// - Throws: An error if the shared secret cannot be computed. This could be due to incompatible keys, incorrect formats, or cryptographic issues specific to the key agreement algorithm.
    func agreeUponZ(privateKey: JWK, publicKey: JWK, ephemeralKey: JWK?, sender: Bool) throws -> Data
}
