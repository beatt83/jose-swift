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

@preconcurrency import CryptoSwift
import CryptoKit
import Foundation
import JSONWebKey
import secp256k1

public struct DataKey {
    public enum SupportedKeyType {
        case rsa
        case curve25519
        case p256
        case p384
        case p521
        case secp256k1
        case octSequence
    }
    
    public let jwk: JWK
    
    public init(type: SupportedKeyType, isPrivate: Bool, isKeyAgreement: Bool, key: Data) throws {
        self.jwk = try buildJWK(type: type, isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, key: key)
    }
}

private func buildJWK(type: DataKey.SupportedKeyType, isPrivate: Bool, isKeyAgreement: Bool, key: Data) throws -> JWK {
    switch type {
    case .rsa:
        return try buildRSA(keyData: key)
    case .p256:
        return try buildP256Key(isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, keyData: key)
    case .p384:
        return try buildP384Key(isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, keyData: key)
    case .p521:
        return try buildP521Key(isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, keyData: key)
    case .curve25519:
        return try buildCurve25519Key(isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, keyData: key)
    case .secp256k1:
        return try buildSecp256k1Key(isPrivate: isPrivate, isKeyAgreement: isKeyAgreement, keyData: key)
    case .octSequence:
        return buildOctetSequence(keyData: key)
    }
}

private func buildOctetSequence(keyData: Data) -> JWK {
    return JWK(keyType: .octetSequence, key: keyData)
}

private func buildRSA(keyData: Data) throws -> JWK {
    return try CryptoSwift.RSA(rawRepresentation: keyData).jwkRepresentation
}

private func buildP256Key(isPrivate: Bool, isKeyAgreement: Bool, keyData: Data) throws -> JWK {
    if isPrivate {
        if !isKeyAgreement {
            return try P256.Signing.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        } else {
            return try P256.KeyAgreement.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        }
    }
    
    if !isKeyAgreement {
        return try P256.Signing.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    } else {
        return try P256.KeyAgreement.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    }
}

private func buildP384Key(isPrivate: Bool, isKeyAgreement: Bool, keyData: Data) throws -> JWK {
    if isPrivate {
        if !isKeyAgreement {
            return try P384.Signing.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        } else {
            return try P384.KeyAgreement.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        }
    }
    
    if !isKeyAgreement {
        return try P384.Signing.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    } else {
        return try P384.KeyAgreement.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    }
}

private func buildP521Key(isPrivate: Bool, isKeyAgreement: Bool, keyData: Data) throws -> JWK {
    if isPrivate {
        if !isKeyAgreement {
            return try P521.Signing.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        } else {
            return try P521.KeyAgreement.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        }
    }
    
    if !isKeyAgreement {
        return try P521.Signing.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    } else {
        return try P521.KeyAgreement.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    }
}

private func buildCurve25519Key(isPrivate: Bool, isKeyAgreement: Bool, keyData: Data) throws -> JWK {
    if isPrivate {
        if !isKeyAgreement {
            return try Curve25519.Signing.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        } else {
            return try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: keyData).jwkRepresentation
        }
    }
    
    if !isKeyAgreement {
        return try Curve25519.Signing.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    } else {
        return try Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: keyData).jwkRepresentation
    }
}

private func buildSecp256k1Key(isPrivate: Bool, isKeyAgreement: Bool, keyData: Data) throws -> JWK {
    if isPrivate {
        if !isKeyAgreement {
            return try secp256k1.Signing.PrivateKey.init(dataRepresentation: keyData, format: .uncompressed).jwkRepresentation
        } else {
            return try secp256k1.KeyAgreement.PrivateKey.init(dataRepresentation: keyData, format: .uncompressed).jwkRepresentation
        }
    }
    
    if !isKeyAgreement {
        return try secp256k1.Signing.PublicKey.init(dataRepresentation: keyData, format: .uncompressed).jwkRepresentation
    } else {
        return try secp256k1.KeyAgreement.PublicKey.init(dataRepresentation: keyData, format: .uncompressed).jwkRepresentation
    }
}
