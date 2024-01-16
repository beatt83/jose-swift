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

struct ECDH1PU {
    func processSharedKey(
        privateKey: JWK,
        publicKey: JWK,
        ephemeralKey: JWK,
        sender: Bool
    ) throws -> Data {
        let ze: Data
        let zs: Data
        
        if sender {
            guard
                let epkAgreement = ephemeralKey.keyAgreement,
                let privateKeyAgreement = privateKey.keyAgreement
            else {
                throw CryptoError.notValidPrivateKey
            }
            
            ze = try epkAgreement
                .sharedSecretFromKeyAgreement(publicKeyShare: publicKey)
            zs = try privateKeyAgreement
                .sharedSecretFromKeyAgreement(publicKeyShare: publicKey)
        } else {
            guard
                let privateKeyAgreement = privateKey.keyAgreement
            else {
                throw CryptoError.notValidPrivateKey
            }
            
            ze = try privateKeyAgreement
                .sharedSecretFromKeyAgreement(publicKeyShare: ephemeralKey)
            zs = try privateKeyAgreement
                .sharedSecretFromKeyAgreement(publicKeyShare: publicKey)
        }
        return ze + zs
    }
}
