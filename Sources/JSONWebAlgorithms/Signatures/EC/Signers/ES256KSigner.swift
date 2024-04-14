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

import Foundation
import JSONWebKey
import secp256k1

public struct ES256KSigner: Signer {
    public enum SignatureFormat {
        case raw
        case der
    }
    
    public static var outputFormat = ES256KSigner.SignatureFormat.raw
    
    public var algorithm: String { SigningAlgorithm.ES256K.rawValue }
    
    public func sign(data: Data, key: JWK) throws -> Data {
        guard let d = key.d else { throw CryptoError.notValidPrivateKey }
        let privateKey = try secp256k1.Signing.PrivateKey(dataRepresentation: d)
        let hash = SHA256.hash(data: data)
        let signature = try privateKey.signature(for: hash)
        
        switch Self.outputFormat {
        case .raw:
            return signature.dataRepresentation
        case .der:
            return try signature.derRepresentation
        }
    }
}
