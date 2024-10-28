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

/// `ES256KVerifier` provides methods to verify signatures using the ES256K algorithm.
public struct ES256KVerifier: Verifier {
    
#if swift(>=6.0)
    /// Indicates whether to use a fail-safe mechanism compatible with Bouncy Castle.
    nonisolated(unsafe) public static var bouncyCastleFailSafe = false
#else
    /// Indicates whether to use a fail-safe mechanism compatible with Bouncy Castle.
    public static var bouncyCastleFailSafe = false
#endif
    /// The algorithm used for verification.
    public var algorithm: String { SigningAlgorithm.ES256K.rawValue }
    
    /// Verifies the given data and signature using the provided public key.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The signature to be verified.
    ///   - key: The `JWK` containing the public key to use for verification.
    /// - Throws: An error if the public key is not valid or if the verification process fails.
    /// - Returns: A boolean value indicating whether the signature is valid.
    public func verify(data: Data, signature: Data, key: JWK?) throws -> Bool {
        guard let x = key?.x, let y = key?.y else { throw CryptoError.notValidPublicKey }
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: [0x04] + x + y, format: .uncompressed)
        let hash = SHA256.hash(data: data)
        let objSignature = try getSignature(signature).normalize
        guard publicKey.isValidSignature(objSignature, for: hash) else {
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
        return try .init(dataRepresentation: signatureInvertedRS).normalize
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

private extension secp256k1.Signing.ECDSASignature {
    /// Convert a signature into a normal signature.
    var normalize: secp256k1.Signing.ECDSASignature {
        get throws {
            let context = secp256k1.Context.rawRepresentation
            var signature = secp256k1_ecdsa_signature()
            var resultSignature = secp256k1_ecdsa_signature()

            dataRepresentation.copyToUnsafeMutableBytes(of: &signature.data)

            guard secp256k1_ecdsa_signature_normalize(
                context,
                &resultSignature,
                &signature
            ) != 0 else {
                return self
            }

            return try secp256k1.Signing.ECDSASignature(dataRepresentation: resultSignature.dataValue)
        }
    }
}
