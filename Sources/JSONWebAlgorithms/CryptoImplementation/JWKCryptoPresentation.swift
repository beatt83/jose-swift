// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation
import JSONWebKey
import secp256k1

/// An extension for `JWK` providing convenience functions for working with `CryptoKit`.
public extension JWK {
    /// Returns a `CryptoKit` representation of the JWK.
    ///
    /// - Parameter type: The type of `CryptoKit` object to return.
    /// - Returns: The `CryptoKit` object.
    /// - Throws: `JWK.Error` if the JWK is not compatible with the specified `CryptoKit` type, or if a required component is missing.
    func cryptoKitRepresentation<T>(type: T.Type) throws -> T {
        guard keyType == .ellipticCurve || keyType == .octetKeyPair else {
            throw JWK.Error.notSupported
        }
        
        switch type {
        case is P256.KeyAgreement.PrivateKey.Type,
            is P384.KeyAgreement.PrivateKey.Type,
            is P521.KeyAgreement.PrivateKey.Type,
            is secp256k1.KeyAgreement.PrivateKey.Type,
            is Curve25519.KeyAgreement.PrivateKey.Type:
            
            guard let d else {
                throw JWK.Error.missingDComponent
            }
            switch type {
            case is P256.KeyAgreement.PrivateKey.Type:
                return try P256.KeyAgreement.PrivateKey(rawRepresentation: d) as! T
            case is P384.KeyAgreement.PrivateKey.Type:
                return try P384.KeyAgreement.PrivateKey(rawRepresentation: d) as! T
            case is P521.KeyAgreement.PrivateKey.Type:
                return try P521.KeyAgreement.PrivateKey(rawRepresentation: d) as! T
            case is secp256k1.KeyAgreement.PrivateKey.Type:
                return try secp256k1.KeyAgreement.PrivateKey(dataRepresentation: d, format: .uncompressed) as! T
            case is Curve25519.KeyAgreement.PrivateKey.Type:
                return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: d) as! T
            default:
                throw JWK.Error.notSupported
            }
            
        case is P256.KeyAgreement.PublicKey.Type,
            is P384.KeyAgreement.PublicKey.Type,
            is P521.KeyAgreement.PublicKey.Type,
            is secp256k1.KeyAgreement.PublicKey.Type:
            
            guard let x else {
                throw JWK.Error.missingXComponent
            }
            guard let y else {
                throw JWK.Error.missingYComponent
            }
            let data = x + y
            print(self.keyID)
            print(x.toHexString())
            print(x.count)
            print(y.toHexString())
            print(y.count)
            switch type {
            case is P256.KeyAgreement.PublicKey.Type:
                return try P256.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is P384.KeyAgreement.PublicKey.Type:
                return try P384.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is P521.KeyAgreement.PublicKey.Type:
                return try P521.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is secp256k1.KeyAgreement.PublicKey.Type:
                // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
                return try secp256k1.KeyAgreement.PublicKey(
                    dataRepresentation: [0x04] + data,
                    format: .uncompressed
                ) as! T
            default:
                throw JWK.Error.notSupported
            }
            
        case is Curve25519.KeyAgreement.PublicKey.Type:
            
            guard let x else {
                throw JWK.Error.missingXComponent
            }
            let data = x
            switch type {
            case is Curve25519.KeyAgreement.PublicKey.Type:
                return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            default:
                throw JWK.Error.notSupported
            }
            
        default:
            throw JWK.Error.notSupported
        }
    }
}
