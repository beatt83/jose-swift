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

/// Extension to make `P384.KeyAgreement.PrivateKey` conform to `SharedKeyAgreement`.
extension P384.KeyAgreement.PrivateKey: SharedKeyAgreement {
    
    /// Computes the shared secret from the key agreement with the provided public key share.
    /// - Parameter publicKeyShare: The public key share as a `JWK`.
    /// - Throws: An error if the conversion to `P384.KeyAgreement.PublicKey` fails or the key agreement fails.
    /// - Returns: The shared secret as a `Data` object.
    public func sharedSecretFromKeyAgreement(
        publicKeyShare: JWK
    ) throws -> Data {
        let sharedSecret = try publicKeyShare.cryptoKitRepresentation(type: P384.KeyAgreement.PublicKey.self)
        return try sharedSecretFromKeyAgreement(with: sharedSecret)
            .withUnsafeBytes { .init($0) }
    }
}
