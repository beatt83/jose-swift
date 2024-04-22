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

public struct ES256KVerifier: Verifier {
    public static var bouncyCastleFailSafe = false
    
    public var algorithm: String { SigningAlgorithm.ES256K.rawValue }
    
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard
            let x = key?.x,
            let y = key?.y
        else { throw CryptoError.notValidPublicKey }
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: [0x04] + x + y, format: .uncompressed)
        let hash = SHA256.hash(data: data)
        guard try publicKey.isValidSignature(getSignature(signature), for: hash) else {
            guard ES256KVerifier.bouncyCastleFailSafe else {
                return false
            }
            let bcSignature = try transcodeBCSignatureToBitcoin(signature: signature)
            return publicKey.isValidSignature(bcSignature, for: hash)
        }
        return true
    }
    
    // This function helps transcode the signature from bouncy castle to bitcoin
    private func transcodeBCSignatureToBitcoin(signature: Data) throws -> secp256k1.Signing.ECDSASignature {
        let signature = try getSignature(signature)
        let signatureInvertedRS = invertR_S(signatureData: signature.dataRepresentation)
        return try .init(dataRepresentation: signatureInvertedRS)
    }
}

private func getSignature(_ data: Data) throws -> secp256k1.Signing.ECDSASignature {
    if let signature = try? secp256k1.Signing.ECDSASignature(dataRepresentation: data){
        return signature
    } else if let signature = try? secp256k1.Signing.ECDSASignature(derRepresentation: data) {
        return signature
    } else if let signature = try? secp256k1.Signing.ECDSASignature(compactRepresentation: data) {
        return signature
    } else {
        throw CryptoError.invalidSignature
    }
}
