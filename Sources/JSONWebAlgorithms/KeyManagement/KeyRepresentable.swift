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

import CryptoSwift
import CryptoKit
import Foundation
import JSONWebKey
import secp256k1

extension JWK {
    public enum KeyFormat {
        case rsa
        case curve25519
        case p256
        case p384
        case p512
        case secp256k1
        case octSequence
    }
    
    public static func JWKFrom<Key>(format: KeyFormat, isPrivate: Bool, isKeyAgreement: Bool, key: Key) throws -> JWK {
        switch key {
        case let value as Data:
            return try getJWKFromData(format: format, isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, value: value)
        case let value as SecKey:
            return try getJWKFromSecKey(format: format, isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, value: value)
        case let value as JWK:
            return value
        default:
            throw isPrivate ? CryptoError.notValidPrivateKey : CryptoError.notValidPublicKey
        }
    }
}

private func getJWKFromData(format: JWK.KeyFormat, isPrivate: Bool, isKeyAgreement: Bool, value: Data) throws -> JWK {
    switch format {
    case .rsa:
        let rsaKey = try CryptoSwift.RSA(rawRepresentation: value)
        let n = rsaKey.n.serialize()
        let e = rsaKey.e.serialize()
        let d = rsaKey.d?.serialize()
        
        return JWK(keyType: .rsa, e: e, n: n, d: d)
    case .curve25519 where isKeyAgreement == false:
        if isPrivate {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try Curve25519.Signing.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .curve25519 where isKeyAgreement == true:
        if isPrivate {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p256 where isKeyAgreement == false:
        if isPrivate {
            return try P256.Signing.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P256.Signing.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p256 where isKeyAgreement == true:
        if isPrivate {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P256.KeyAgreement.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p384 where isKeyAgreement == false:
        if isPrivate {
            return try P384.Signing.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P384.Signing.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p384 where isKeyAgreement == true:
        if isPrivate {
            return try P384.KeyAgreement.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P384.KeyAgreement.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p512 where isKeyAgreement == false:
        if isPrivate {
            return try P521.Signing.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P521.Signing.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .p512 where isKeyAgreement == true:
        if isPrivate {
            return try P521.KeyAgreement.PrivateKey(rawRepresentation: value).jwkRepresentation
        } else {
            return try P521.KeyAgreement.PublicKey(rawRepresentation: value).jwkRepresentation
        }
    case .secp256k1 where isKeyAgreement == false:
        if isPrivate {
            return try secp256k1.Signing.PrivateKey(dataRepresentation: value).jwkRepresentation
        } else {
            return try secp256k1.Signing.PublicKey(dataRepresentation: value, format: .uncompressed).jwkRepresentation
        }
    case .secp256k1 where isKeyAgreement == true:
        if isPrivate {
            return try secp256k1.KeyAgreement.PrivateKey(dataRepresentation: value).jwkRepresentation
        } else {
            return try secp256k1.KeyAgreement.PublicKey(dataRepresentation: value, format: .uncompressed).jwkRepresentation
        }
    case .octSequence:
        return JWK(keyType: .octetSequence, key: value)
    default:
        throw isPrivate ? CryptoError.notValidPrivateKey : CryptoError.notValidPublicKey
    }
}

private func getJWKFromSecKey(format: JWK.KeyFormat, isPrivate: Bool, isKeyAgreement: Bool, value: SecKey) throws -> JWK {
    let data = try convertSecKeyToData(value)
    return try getJWKFromData(format: format, isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, value: data)
}

private func convertSecKeyToData(_ secKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) else {
        throw CryptoError.securityLayerError(internalStatus: nil, internalError: error?.takeRetainedValue())
    }

    return keyData as Data
}
