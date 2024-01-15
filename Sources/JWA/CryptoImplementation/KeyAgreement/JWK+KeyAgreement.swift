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
import JWK
import secp256k1

extension JWK {
    var keyAgreement: SharedKeyAgreement? {
        switch keyType {
        case .ellipticCurve:
            switch curve {
            case .p256:
                return try? cryptoKitRepresentation(type: P256.KeyAgreement.PrivateKey.self)
            case .p384:
                return try? cryptoKitRepresentation(type: P384.KeyAgreement.PrivateKey.self)
            case .p521:
                return try? cryptoKitRepresentation(type: P521.KeyAgreement.PrivateKey.self)
            case .secp256k1:
                return try? cryptoKitRepresentation(type: secp256k1.KeyAgreement.PrivateKey.self)
            default:
                return nil
            }
        case .octetKeyPair:
            switch curve {
            case .x25519:
                return try? cryptoKitRepresentation(type: Curve25519.KeyAgreement.PrivateKey.self)
            default:
                return nil
            }
        default:
            return nil
        }
    }
}
