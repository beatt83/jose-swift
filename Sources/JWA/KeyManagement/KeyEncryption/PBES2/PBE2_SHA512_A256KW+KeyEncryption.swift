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
import JWK

struct PBE2_SHA512_A256KW: KeyWrapping, KeyUnwrapping {
    
    func generateInitializationVector() throws -> Data {
        Data()
    }
    
    func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata {
        let encryptionResult = try PBES2SHAKeyWrapper.encrypt(
            cek: cek,
            using: using,
            algorithmData: try KeyManagementAlgorithm.pbes2HS512A256KW.rawValue.tryToData(),
            input: arguments.pbs2saltInput,
            count: arguments.pbs2saltCount,
            variant: .sha2(.sha512)
        )
        
        return .init(
            encryptedKey: encryptionResult.encrypedKey,
            pbs2saltInput: encryptionResult.input,
            pbs2saltCount: encryptionResult.count
        )
    }
    
    func contentKeyDecrypt(
        encryptedKey: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> Data {
        guard
            let input = arguments.pbs2saltInput,
            let count = arguments.pbs2saltCount
        else {
            throw CryptoError.missingPBS2SaltInputOrCount
        }
        
        return try PBES2SHAKeyWrapper.decrypt(
            encryptedKey: encryptedKey,
            using: using,
            algorithmData: try KeyManagementAlgorithm.pbes2HS512A256KW.rawValue.tryToData(),
            input: input,
            count: count,
            variant: .sha2(.sha512)
        )
    }
}
