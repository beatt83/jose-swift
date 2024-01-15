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

/// `JWARegisteredFieldsHeader` is a protocol that defines a set of fields commonly used in JSON Web Algorithms (JWA).
/// These fields are typically used in cryptographic operations such as key agreement or key derivation.
public protocol JWARegisteredFieldsHeader: Codable {
    /// The ephemeral public key, often used in key agreement protocols.
    /// This key is typically short-lived and used for a single session or transaction.
    var ephemeralPublicKey: JWK? { get set }

    /// PartyUInfo (User Information) data, used in key agreement protocols to provide additional context or information.
    /// This data is typically combined with the ephemeral public key during key derivation.
    var agreementPartyUInfo: Data? { get set }

    /// PartyVInfo (Voucher Information) data, used in key agreement protocols alongside PartyUInfo.
    /// It also provides additional context or information during key derivation.
    var agreementPartyVInfo: Data? { get set }

    /// The Initialization Vector (IV) used in certain encryption algorithms to provide additional randomness.
    /// IVs are critical for ensuring that the same plaintext encrypts differently each time.
    var initializationVector: Data? { get set }

    /// The authentication tag, which is used to verify the integrity and authenticity of a message in authenticated encryption.
    /// It's essential for detecting data tampering.
    var authenticationTag: Data? { get set }

    /// PBES2 (Password-Based Encryption Scheme 2) salt input, used in key derivation functions.
    /// The salt ensures that the same password generates different encryption keys each time.
    var pbes2SaltInput: Data? { get set }

    /// The iteration count for the PBES2 salt input, determining how many times the password is hashed during the key derivation process.
    /// Higher counts provide better security but require more computational resources.
    var pbes2SaltCount: Data? { get set }
}
