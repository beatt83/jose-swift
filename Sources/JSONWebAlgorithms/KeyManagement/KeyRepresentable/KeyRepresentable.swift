import Crypto
@preconcurrency import CryptoSwift
import Foundation
import JSONWebKey
import secp256k1
#if canImport(Security)
import Security
#endif

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

#if canImport(Security)
extension SecKey: KeyRepresentable {
    public var jwk: JWK {
        get throws {
            try SecKeyExtended(secKey: self).jwk()
        }
    }
}
#endif
