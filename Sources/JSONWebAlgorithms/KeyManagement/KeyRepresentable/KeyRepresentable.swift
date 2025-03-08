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
@preconcurrency import CryptoSwift
import Foundation
import JSONWebKey
import secp256k1

public protocol KeyRepresentable {
    var jwk: JWK { get throws }
}

extension JWK: KeyRepresentable {
    public var jwk: JWK { self }
}

extension RSA: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}

extension Curve25519.Signing.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension Curve25519.Signing.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension Curve25519.KeyAgreement.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension Curve25519.KeyAgreement.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P256.Signing.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P256.Signing.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P256.KeyAgreement.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P256.KeyAgreement.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P384.Signing.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P384.Signing.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P384.KeyAgreement.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P384.KeyAgreement.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P521.Signing.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P521.Signing.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P521.KeyAgreement.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension P521.KeyAgreement.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension secp256k1.Signing.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension secp256k1.Signing.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension secp256k1.KeyAgreement.PrivateKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension secp256k1.KeyAgreement.PublicKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension SymmetricKey: KeyRepresentable {
    public var jwk: JWK { self.jwkRepresentation }
}
extension SecKey: KeyRepresentable {
    public var jwk: JWK {
        get throws {
            try SecKeyExtended(secKey: self).jwk()
        }
    }
}
