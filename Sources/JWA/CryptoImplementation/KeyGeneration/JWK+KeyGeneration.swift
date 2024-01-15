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

/// Extension of `JWK` to provide key generation functionality based on the key type and curve.
extension JWK {
    /// Provides a `KeyGeneration` instance suitable for the specific key type and curve of the JWK.
    /// This property allows for generating cryptographic keys based on the characteristics of the JWK.
    /// - Returns: An instance conforming to the `KeyGeneration` protocol, or `nil` if key generation is not supported for the specific key type and curve.
    public var keyGeneration: KeyGeneration? {
        switch keyType {
        case .ellipticCurve:
            switch curve {
            case .p256:
                // Provides a key generation instance for the P-256 elliptic curve.
                return P256KeyGeneration()
            case .p384:
                // Provides a key generation instance for the P-384 elliptic curve.
                return P384KeyGeneration()
            case .p521:
                // Provides a key generation instance for the P-521 elliptic curve.
                return P521KeyGeneration()
            case .secp256k1:
                // Provides a key generation instance for the SECP256k1 elliptic curve, commonly used in blockchain and cryptocurrency contexts.
                return Secp256k1KeyGeneration()
            default:
                // If the elliptic curve is not recognized or supported for key generation.
                return nil
            }
        case .octetKeyPair:
            switch curve {
            case .x25519, .ed25519:
                // Provides a key generation instance for Curve25519, suitable for modern, efficient elliptic curve cryptography.
                return Curve25519KeyGeneration()
            default:
                // If the curve is not recognized or supported for octet key pairs.
                return nil
            }
        default:
            // If the key type is not supported for key generation.
            return nil
        }
    }
}
