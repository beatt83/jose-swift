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
import secp256k1

struct ES256KVerifier: Verifier {
    var algorithm: String { AvailableCrypto.SECP256K1_ECDSA_WithSHA256.algorithm }
    var algorithmDescription: String { AvailableCrypto.SECP256K1_ECDSA_WithSHA256.algorithmDescription }
    
    func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard
            let x = key?.x,
            let y = key?.y
        else { throw CryptoError.notValidPublicKey }
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: x + y, format: .uncompressed)
        let hash = SHA256.hash(data: data)
        return try publicKey.isValidSignature(getSignature(signature), for: hash)
    }
}

private func getSignature(_ data: Data) throws -> secp256k1.Signing.ECDSASignature {
    if let signature = try? secp256k1.Signing.ECDSASignature(dataRepresentation: data){
        return signature
    } else if let signature = try? secp256k1.Signing.ECDSASignature(derRepresentation: data) {
        return signature
    } else if let signature = try? secp256k1.Signing.ECDSASignature(compactRepresentation: data) {
        return signature
    } else {
        throw CryptoError.invalidSignature
    }
}
