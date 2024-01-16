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
import JSONWebAlgorithms
import JSONWebKey

extension JWK {
    func signingAlgorithm() throws -> SigningAlgorithm {
        switch keyType {
        case .rsa:
            switch algorithm {
            case SigningAlgorithm.RS256.rawValue:
                return SigningAlgorithm.RS256
            case SigningAlgorithm.RS384.rawValue:
                return SigningAlgorithm.RS384
            case SigningAlgorithm.RS512.rawValue:
                return SigningAlgorithm.RS512
            case SigningAlgorithm.PS256.rawValue:
                return SigningAlgorithm.PS256
            case SigningAlgorithm.PS384.rawValue:
                return SigningAlgorithm.PS384
            case SigningAlgorithm.PS512.rawValue:
                return SigningAlgorithm.PS512
            default:
                throw JWS.JWSError.unsupportedAlgorithm(keyType: keyType.rawValue, algorithm: algorithm)
            }
        case .ellipticCurve:
            guard let curve else { throw JWS.JWSError.missingCurve }
            switch curve {
            case .p256:
                return SigningAlgorithm.ES256
            case .p384:
                return SigningAlgorithm.ES384
            case .p521:
                return SigningAlgorithm.ES512
            case .secp256k1:
                return SigningAlgorithm.ES256K
            default:
                throw JWS.JWSError.unsupportedAlgorithm(keyType: keyType.rawValue, algorithm: algorithm, curve: curve.rawValue)
            }
        case .octetSequence:
            switch algorithm {
            case SigningAlgorithm.HS256.rawValue:
                return SigningAlgorithm.HS256
            case SigningAlgorithm.HS384.rawValue:
                return SigningAlgorithm.HS384
            case SigningAlgorithm.HS512.rawValue:
                return SigningAlgorithm.HS512
            default:
                throw JWS.JWSError.unsupportedAlgorithm(keyType: keyType.rawValue, algorithm: algorithm, curve: curve?.rawValue)
            }
        default:
            throw JWS.JWSError.unsupportedAlgorithm(keyType: keyType.rawValue, algorithm: algorithm, curve: curve?.rawValue)
        }
    }
}
