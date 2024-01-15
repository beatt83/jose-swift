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
import JWK
import secp256k1

struct Secp256k1KeyGeneration: KeyGeneration {

    public func generateRandomKey() throws -> Data {
        return try SecureRandom.secureRandomData(count: 32)
    }

    public func generatePrivateKey(purpose: KeyGenerationPurpose) throws -> Data {
        switch purpose {
        case .signing:
            return try secp256k1.Signing.PrivateKey().dataRepresentation
        case .keyAgreement:
            return try secp256k1.KeyAgreement.PrivateKey().rawRepresentation
        }
    }

    public func generateKeyPairJWK(purpose: KeyGenerationPurpose) throws -> JWK {
        switch purpose {
        case .signing:
            return try secp256k1.Signing.PrivateKey().jwkRepresentation
        case .keyAgreement:
            return try secp256k1.KeyAgreement.PrivateKey().jwkRepresentation
        }
    }
}
