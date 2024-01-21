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

/// Enumerates possible arguments for key derivation processes.
public enum KeyDerivationArguments {
    /// Specifies the initial key material for the key derivation.
    case key(Data)

    /// Specifies the length in bits of the key to be derived.
    case keyLengthInBits(Int)

    /// Specifies the algorithm identifier data used in key derivation.
    case algorithmId(Data)

    /// Contains data specific to party U involved in the key agreement.
    case partyUInfo(Data)

    /// Contains data specific to party V involved in the key agreement.
    case partyVInfo(Data)

    /// A tag that can be used to ensure the integrity of the derived key.
    case tag(Data)

    /// Password or passphrase used in the derivation process.
    case password(Data)

    /// Salt input for the derivation process.
    case saltInput(Data)

    /// The iteration count for key derivation algorithms that use a salt.
    case saltCount(Int)

    /// Allows for custom data to be included, identified by a key.
    case customData(key: String, value: Data)

    /// Allows for a custom JSON Web Key (JWK) to be included, identified by a key.
    case customJWK(key: String, value: JWK)
}

/// `KeyDerivation` is a protocol defining functionality for deriving cryptographic keys.
/// It is used in scenarios where keys need to be derived from existing material, such as passwords or shared secrets.
public protocol KeyDerivation {
    /// Derives a cryptographic key based on the provided arguments.
    ///
    /// - Parameter arguments: An array of `KeyDerivationArguments` that specify the parameters for the key derivation.
    /// - Returns: The derived key as a `Data` object.
    /// - Throws: An error if the key derivation process fails.
    func deriveKey(arguments: [KeyDerivationArguments]) throws -> Data
}

extension Array where Element == KeyDerivationArguments {
    var key: Data? {
        return self.compactMap {
            if case .key(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var keyLengthInBits: Int? {
        return self.compactMap {
            if case .keyLengthInBits(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var algorithmId: Data? {
        return self.compactMap {
            if case .algorithmId(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var partyUInfo: Data? {
        return self.compactMap {
            if case .partyUInfo(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
    
    var partyVInfo: Data? {
        return self.compactMap {
            if case .partyVInfo(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var tag: Data? {
        return self.compactMap {
            if case .tag(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var password: Data? {
        return self.compactMap {
            if case .password(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
    
    var saltInput: Data? {
        return self.compactMap {
            if case .saltInput(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
    
    var saltCount: Int? {
        return self.compactMap {
            if case .saltCount(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
}
