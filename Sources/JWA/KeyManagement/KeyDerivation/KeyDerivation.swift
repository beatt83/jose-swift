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

/// `KeyDerivation` is a protocol defining functionality for deriving cryptographic keys.
public protocol KeyDerivation {
    /// Derives a key from the given input parameters using a specified key derivation function.
    /// - Parameters:
    ///   - key: The input key material used for derivation.
    ///   - keyLengthInBits: The desired length of the derived key in bits.
    ///   - algorithmId: An identifier for the key derivation algorithm.
    ///   - partyUInfo: Data specific to one party involved in the key derivation (usually the initiator).
    ///   - partyVInfo: Data specific to the other party involved in the key derivation (usually the responder).
    ///   - tag: A tag used in the key derivation process, providing additional context or information.
    ///   - other: A dictionary containing other relevant data for key derivation.
    /// - Returns: The derived key as `Data`.
    /// - Throws: An error if key derivation fails. This could be due to incorrect input parameters, unsupported algorithm specifications, or other cryptographic issues.
    func deriveKey(
        key: Data,
        keyLengthInBits: Int,
        algorithmId: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        tag: Data,
        other: [String: Data]
    ) throws -> Data
}

extension KeyDerivation {
    /// Provides a default implementation of `deriveKey` with optional parameters set to their default values.
    /// - Parameters:
    ///   - key: The input key material used for derivation.
    ///   - keyLengthInBits: The desired length of the derived key in bits.
    ///   - algorithmId: An optional identifier for the key derivation algorithm (default is empty).
    ///   - partyUInfo: Optional data specific to one party involved in the key derivation (default is empty).
    ///   - partyVInfo: Optional data specific to the other party involved in the key derivation (default is empty).
    ///   - tag: An optional tag used in the key derivation process (default is empty).
    ///   - other: An optional dictionary containing other relevant data for key derivation (default is empty).
    /// - Returns: The derived key as `Data`.
    /// - Throws: An error if key derivation fails.
    public func deriveKey(
        key: Data,
        keyLengthInBits: Int,
        algorithmId: Data = Data(),
        partyUInfo: Data = Data(),
        partyVInfo: Data = Data(),
        tag: Data = Data(),
        other: [String: Data] = [:]
    ) throws -> Data {
        try self.deriveKey(
            key: key,
            keyLengthInBits: keyLengthInBits,
            algorithmId: algorithmId,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            tag: tag,
            other: other
        )
    }
}
