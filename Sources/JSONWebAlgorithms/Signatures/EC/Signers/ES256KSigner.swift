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

struct ES256KSigner: Signer {
    var algorithm: String { AvailableCrypto.SECP256K1_ECDSA_WithSHA256.algorithm }
    var algorithmDescription: String { AvailableCrypto.SECP256K1_ECDSA_WithSHA256.algorithmDescription }
    
    func sign(data: Data, key: JWK) throws -> Data {
        guard let d = key.d else { throw CryptoError.notValidPrivateKey }
        let privateKey = try secp256k1.Signing.PrivateKey(dataRepresentation: d)
        let hash = SHA256.hash(data: data)
        return try privateKey.signature(for: hash).dataRepresentation
    }
}
