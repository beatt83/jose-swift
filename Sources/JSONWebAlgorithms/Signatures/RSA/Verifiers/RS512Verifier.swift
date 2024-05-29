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

import CryptoSwift
import Foundation
import JSONWebKey

/// `RS512Verifier` provides methods to verify signatures using the RS512 algorithm.
public struct RS512Verifier: Verifier {
    
    /// The algorithm used for verification.
    public var algorithm: String { SigningAlgorithm.RS512.rawValue }
    
    /// Verifies the given data and signature using the provided public key.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The signature to be verified.
    ///   - key: The `JWK` containing the public key to use for verification.
    /// - Throws: An error if the public key is not valid or if the verification process fails.
    /// - Returns: A boolean value indicating whether the signature is valid.
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard let n = key?.n, let e = key?.e else { throw CryptoError.notValidPrivateKey }
        let publicKey: RSA
        if let p = key?.p, let q = key?.q, let d = key?.d {
            publicKey = try RSA(n: BigUInteger(n), e: BigUInteger(e), d: BigUInteger(d), p: BigUInteger(p), q: BigUInteger(q))
        } else {
            publicKey = RSA(n: BigUInteger(n), e: BigUInteger(e), d: key?.d.map { BigUInteger($0) })
        }
        
        return try publicKey.verify(signature: signature.bytes, for: data.bytes, variant: .message_pkcs1v15_SHA512)
    }
}
