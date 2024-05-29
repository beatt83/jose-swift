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

/// Extension to make `ECDHES` conform to `KeyAgreementZ`.
extension ECDHES: KeyAgreementZ {
    
    /// Agrees upon a shared secret `Z` using the given private and public keys.
    /// - Parameters:
    ///   - privateKey: The private key as a `JWK`.
    ///   - publicKey: The public key as a `JWK`.
    ///   - ephemeralKey: The ephemeral key as a `JWK`. This parameter is optional and not used in this implementation.
    ///   - sender: A boolean indicating if the sender is agreeing upon the shared secret. This parameter is not used in this implementation.
    /// - Throws: An error if the key agreement fails.
    /// - Returns: The agreed upon shared secret `Z` as a `Data` object.
    public func agreeUponZ(privateKey: JWK, publicKey: JWK, ephemeralKey: JWK?, sender: Bool) throws -> Data {
        return try processSharedKey(privateKey: privateKey, publicKey: publicKey)
    }
}
