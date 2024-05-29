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

/// `PBE2_SHA256_A128KW` provides methods to derive a key using the PBES2-HMAC-SHA256 algorithm with AES key wrapping.
struct PBE2_SHA256_A128KW: KeyDerivation {
    
    /// Derives a key using the provided key derivation arguments.
    /// - Parameter arguments: An array of `KeyDerivationArguments` containing the necessary parameters for key derivation.
    /// - Throws: An error if required arguments are missing or if the key derivation fails.
    /// - Returns: The derived key as a `Data` object.
    public func deriveKey(arguments: [KeyDerivationArguments]) throws -> Data {
        guard let password = arguments.password else {
            throw CryptoError.missingArguments(["password"])
        }
        guard let salt = arguments.saltInput, let count = arguments.saltCount else {
            throw CryptoError.missingPBS2SaltInputOrCount
        }
        
        return try PBES2SHAKeyDerivation.derive(
            password: password,
            saltInput: salt,
            saltCount: count,
            variant: .sha2(.sha256)
        ).derivedKey
    }
}
