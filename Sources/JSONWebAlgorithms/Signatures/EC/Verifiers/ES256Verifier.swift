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

public struct ES256Verifier: Verifier {
    public var algorithm: String { SigningAlgorithm.ES256.rawValue }
    
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard
            let x = key?.x,
            let y = key?.y
        else { throw CryptoError.notValidPublicKey }
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: x + y)
        let hash = SHA256.hash(data: data)
        return try publicKey.isValidSignature(getSignature(signature), for: hash)
    }
}

private func getSignature(_ data: Data) throws -> P256.Signing.ECDSASignature {
    if let signature = try? P256.Signing.ECDSASignature(rawRepresentation: data) {
        return signature
    } else if let signature = try? P256.Signing.ECDSASignature(derRepresentation: data) {
        return signature
    } else {
        throw CryptoError.invalidSignature
    }
}
