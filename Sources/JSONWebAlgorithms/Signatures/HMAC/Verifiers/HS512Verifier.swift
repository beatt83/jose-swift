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

import Crypto
import Foundation
import JSONWebKey

/// `HS512Verifier` provides methods to verify signatures using the HS512 algorithm.
public struct HS512Verifier: Verifier {
    
    /// The algorithm used for verification.
    public var algorithm: String { SigningAlgorithm.HS512.rawValue }
    
    /// Verifies the given data and signature using the provided symmetric key.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The signature to be verified.
    ///   - key: The `JWK` containing the symmetric key to use for verification.
    /// - Throws: An error if the symmetric key is not valid or if the verification process fails.
    /// - Returns: A boolean value indicating whether the signature is valid.
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard let k = key?.key else { throw CryptoError.notValidPrivateKey }
        let symmetryKey = SymmetricKey(data: k)
        return HMAC<SHA512>.isValidAuthenticationCode(signature, authenticating: data, using: symmetryKey)
    }
}
