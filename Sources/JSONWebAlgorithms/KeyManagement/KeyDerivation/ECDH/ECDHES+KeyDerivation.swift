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

import Crypto
import Foundation
import Tools

/// Extension to make `ECDHES` conform to `KeyDerivation`.
extension ECDHES: KeyDerivation {
    
    /// Derives a key using the provided key derivation arguments.
    /// - Parameter arguments: An array of `KeyDerivationArguments` containing the necessary parameters for key derivation.
    /// - Throws: An error if required arguments are missing or if the key derivation fails.
    /// - Returns: The derived key as a `Data` object.
    public func deriveKey(arguments: [KeyDerivationArguments]) throws -> Data {
        guard let key = arguments.key else {
            throw CryptoError.missingArguments(["key"])
        }
        let algorithmId = arguments.algorithmId ?? .init()
        let partyUInfo = arguments.partyUInfo ?? .init()
        let partyVInfo = arguments.partyVInfo ?? .init()
        let keyLengthInBits = arguments.keyLengthInBits ?? 0
        
        let algorithmIDData = UInt32(algorithmId.count).bigEndian.dataRepresentation + algorithmId
        let partyUInfoData = UInt32(partyUInfo.count).bigEndian.dataRepresentation + partyUInfo
        let partyVInfoData = UInt32(partyVInfo.count).bigEndian.dataRepresentation + partyVInfo
        let suppPubInfoData = UInt32(keyLengthInBits).bigEndian.dataRepresentation
        let suppPrivInfoData = Data()
        let tagData = Data()

        return try ConcatKDF<Crypto.SHA256>.deriveKey(
            z: key,
            keyDataLen: keyLengthInBits,
            algorithmID: algorithmIDData,
            partyUInfo: partyUInfoData,
            partyVInfo: partyVInfoData,
            suppPubInfo: suppPubInfoData,
            suppPrivInfo: suppPrivInfoData,
            tag: tagData
        )
    }
}
