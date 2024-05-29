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

/// `ES512Signer` provides methods to sign data using the ES512 algorithm.
public struct ES512Signer: Signer {
    
    /// The algorithm used for signing.
    public var algorithm: String { SigningAlgorithm.ES512.rawValue }
    
    /// Signs the given data using the provided private key.
    /// - Parameters:
    ///   - data: The data to be signed.
    ///   - key: The `JWK` containing the private key to use for signing.
    /// - Throws: An error if the private key is not valid or if the signing process fails.
    /// - Returns: The signature as a `Data` object.
    public func sign(data: Data, key: JWK) throws -> Data {
        guard let d = key.d else { throw CryptoError.notValidPrivateKey }
        let privateKey = try P521.Signing.PrivateKey(rawRepresentation: d)
        let hash = SHA512.hash(data: data)
        return try privateKey.signature(for: hash).rawRepresentation
    }
}
