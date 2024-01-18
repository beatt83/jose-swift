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
import Foundation
import JSONWebKey

struct PS512Signer: Signer {
    var algorithm: String { SigningAlgorithm.PS512.rawValue }
    
    func sign(data: Data, key: JWK) throws -> Data {
        guard
            let n = key.n,
            let e = key.e
        else { throw CryptoError.notValidPrivateKey }
        let privateKey: RSA
        if
            let p = key.p,
            let q = key.q,
            let d = key.d
        {
            privateKey = try RSA(n: BigUInteger(n), e: BigUInteger(e), d: BigUInteger(d), p: BigUInteger(p), q: BigUInteger(q))
        } else {
            privateKey = RSA(n: BigUInteger(n), e: BigUInteger(e), d: key.d.map {BigUInteger($0)})
        }
        
        let secKey = try privateKey.getSecKey()
        guard SecKeyIsAlgorithmSupported(secKey, .sign, .rsaSignatureMessagePSSSHA512) else {
            throw CryptoError.algorithmNotSupported(alg: SecKeyAlgorithm.rsaSignatureMessagePSSSHA512.rawValue as String)
        }
        
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(secKey, .rsaSignatureMessagePSSSHA512, data as CFData, &signingError) else {
            let error = signingError?.takeRetainedValue() as? NSError
            throw CryptoError.securityLayerError(internalStatus: error?.code, internalError: error)
        }

        return signature as Data
    }
}
