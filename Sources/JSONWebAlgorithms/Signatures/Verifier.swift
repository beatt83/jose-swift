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

/// `Verifier` defines the requirements for an object that can verify signatures using a specific algorithm.
public protocol Verifier {
    
    /// The algorithm used for verification.
    var algorithm: String { get }
    
    /// Verifies the given data and signature using the provided key.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The signature to be verified.
    ///   - key: The `JWK` containing the key to use for verification.
    /// - Throws: An error if the verification process fails.
    /// - Returns: A boolean value indicating whether the signature is valid.
    func verify(data: Data, signature: Data, key: JWK?) throws -> Bool
}
