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
import Tools

extension ECDHES: KeyDerivation {
    func deriveKey(
        key: Data,
        keyLengthInBits: Int,
        algorithmId: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        tag: Data,
        other: [String : Data]
    ) throws -> Data {
        let algorithmIDData = UInt32(algorithmId.count).bigEndian.dataRepresentation + algorithmId
        let partyUInfoData = UInt32(partyUInfo.count).bigEndian.dataRepresentation + partyUInfo
        let partyVInfoData = UInt32(partyVInfo.count).bigEndian.dataRepresentation + partyVInfo
        let suppPubInfoData = UInt32(keyLengthInBits).bigEndian.dataRepresentation
        let suppPrivInfoData = Data()
        let tagData = Data()

        return try ConcatKDF<CryptoKit.SHA256>.deriveKey(
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
