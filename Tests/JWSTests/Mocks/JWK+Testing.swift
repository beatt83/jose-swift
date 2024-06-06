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
import JSONWebKey
import secp256k1

extension JWK {
    static var testingES256Pair: JWK {
        let privateKey = P256.Signing.PrivateKey()
        return privateKey.jwkRepresentation
    }
    
    static var testingES256PairData: Data {
        let privateKey = P256.Signing.PrivateKey()
        return privateKey.rawRepresentation
    }
    
    static var testingES256PairSecKey: SecKey {
        let p256Data = P256.Signing.PrivateKey().x963Representation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256
        ]

        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(p256Data as CFData, attributes as CFDictionary, &error) {
            return secKey
        } else if let error = error?.takeRetainedValue() {
            fatalError()
        }
        fatalError()
    }
    
    static var testingES384Pair: JWK {
        let privateKey = P384.Signing.PrivateKey()
        return privateKey.jwkRepresentation
    }
    
    static var testingES384PairData: Data {
        let privateKey = P384.Signing.PrivateKey()
        return privateKey.rawRepresentation
    }
    
    static var testingES521Pair: JWK {
        let privateKey = P521.Signing.PrivateKey()
        return privateKey.jwkRepresentation
    }
    
    static var testingES521PairData: Data {
        let privateKey = P521.Signing.PrivateKey()
        return privateKey.rawRepresentation
    }
    
    static var testingCurve25519KPair: JWK {
        let privateKey = Curve25519.Signing.PrivateKey()
        return privateKey.jwkRepresentation
    }
    
    static var testingCurve25519PairData: Data {
        let privateKey = Curve25519.Signing.PrivateKey()
        return privateKey.rawRepresentation
    }
    
    static var testingES256KPair: JWK {
        let privateKey = try! secp256k1.Signing.PrivateKey()
        return privateKey.jwkRepresentation
    }
    
    static var testingES256KPairData: Data {
        let privateKey = try! secp256k1.Signing.PrivateKey()
        return privateKey.dataRepresentation
    }
}
