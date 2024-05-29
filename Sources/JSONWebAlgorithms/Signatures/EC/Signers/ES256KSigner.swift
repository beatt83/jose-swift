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

/// `ES256KSigner` provides methods to sign data using the ES256K algorithm.
public struct ES256KSigner: Signer {
    
    /// Enum representing the signature format.
    public enum SignatureFormat {
        /// Raw format.
        case raw
        /// DER format.
        case der
    }
    
    /// The output format of the signature.
    public static var outputFormat = ES256KSigner.SignatureFormat.raw
    /// Indicates whether the bytes R and S are inverted.
    public static var invertedBytesR_S = false
    
    /// The algorithm used for signing.
    public var algorithm: String { SigningAlgorithm.ES256K.rawValue }
    
    /// Signs the given data using the provided private key.
    /// - Parameters:
    ///   - data: The data to be signed.
    ///   - key: The `JWK` containing the private key to use for signing.
    /// - Throws: An error if the private key is not valid or if the signing process fails.
    /// - Returns: The signature as a `Data` object.
    public func sign(data: Data, key: JWK) throws -> Data {
        guard let d = key.d else { throw CryptoError.notValidPrivateKey }
        let privateKey = try secp256k1.Signing.PrivateKey(dataRepresentation: d)
        let hash = SHA256.hash(data: data)
        let signature = try privateKey.signature(for: hash)
        
        switch Self.outputFormat {
        case .raw:
            guard !Self.invertedBytesR_S else {
                return invertR_S(signatureData: signature.dataRepresentation)
            }
            return signature.dataRepresentation
        case .der:
            guard !Self.invertedBytesR_S else {
                let inverted = invertR_S(signatureData: signature.dataRepresentation)
                let signature = try secp256k1.Signing.ECDSASignature(dataRepresentation: inverted)
                return try signature.derRepresentation
            }
            return try signature.derRepresentation
        }
    }
}

func invertR_S(signatureData: Data) -> Data {
    let (r, s) = extractRS(from: signatureData)
    return Data(r.reversed()) + Data(s.reversed())
}

private func extractRS(from signature: Data) -> (r: Data, s: Data) {
    let rIndex = signature.startIndex
    let sIndex = signature.index(rIndex, offsetBy: 32)
    let r = signature[rIndex..<sIndex]
    let s = signature[sIndex..<signature.endIndex]
    return (r, s)
}
