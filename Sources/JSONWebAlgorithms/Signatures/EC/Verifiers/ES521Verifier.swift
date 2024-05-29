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

/// `ES521Verifier` provides methods to verify signatures using the ES521 algorithm.
public struct ES521Verifier: Verifier {
    
    /// The algorithm used for verification.
    public var algorithm: String { SigningAlgorithm.ES512.rawValue }
    
    /// Verifies the given data and signature using the provided public key.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The signature to be verified.
    ///   - key: The `JWK` containing the public key to use for verification.
    /// - Throws: An error if the public key is not valid or if the verification process fails.
    /// - Returns: A boolean value indicating whether the signature is valid.
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard let x = key?.x, let y = key?.y else { throw CryptoError.notValidPublicKey }
        let publicKey = try P521.Signing.PublicKey(rawRepresentation: x + y)
        let hash = SHA512.hash(data: data)
        return try publicKey.isValidSignature(getSignature(signature), for: hash)
    }
}

private func getSignature(_ data: Data) throws -> P521.Signing.ECDSASignature {
    if let signature = try? P521.Signing.ECDSASignature(rawRepresentation: data) {
        return signature
    } else if let signature = try? P521.Signing.ECDSASignature(derRepresentation: data) {
        return signature
    } else {
        throw CryptoError.invalidSignature
    }
}
