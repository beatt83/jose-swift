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
            let bcSignature = transcodeSignatureToDERBitcoin(derEncodedSig: signature)
            return try publicKey.isValidSignature(getSignature(bcSignature), for: hash)
        }
        return true
    }
    
    // This function helps transcode the signature from bouncy castle to bitcoin
    private func transcodeSignatureToDERBitcoin(derEncodedSig: Data) -> Data {
        // Helper to extract integer components from DER format
        func extractInteger(from data: Data, at offset: inout Int) -> Data {
            guard data[offset] == 0x02 else {
                fatalError("Expected integer")
            }
            offset += 1 // Move past the 0x02
            
            let length = Int(data[offset])
            offset += 1 // Move past the length byte
            
            let integerData = data[offset..<(offset + length)]
            offset += length // Move past the integer data
            return Data(integerData.reversed()) // Reverse the bytes
        }
        
        var offset = 0
        
        // Verify initial DER sequence byte and length
        guard derEncodedSig[offset] == 0x30 else {
            fatalError("Invalid DER encoding")
        }
        offset += 1
        
        let _ = Int(derEncodedSig[offset]) // Total length (not used)
        offset += 1
        
        // Extract and reverse R and S
        let reversedR = extractInteger(from: derEncodedSig, at: &offset)
        let reversedS = extractInteger(from: derEncodedSig, at: &offset)
        
        // Re-encode to DER format
        var derEncoded = Data([0x30]) // Start of DER sequence
        let totalLength = reversedR.count + reversedS.count + 4 // Total length of the content
        derEncoded.append(contentsOf: [UInt8(totalLength)])
        
        // Append R
        derEncoded.append(contentsOf: [0x02, UInt8(reversedR.count)])
        derEncoded.append(reversedR)
        
        // Append S
        derEncoded.append(contentsOf: [0x02, UInt8(reversedS.count)])
        derEncoded.append(reversedS)
        
        return derEncoded
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
