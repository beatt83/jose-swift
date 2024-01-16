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
import Tools

struct AESKeyWrap: KeyWrapping {
    func generateInitializationVector() throws -> Data {
        Data()
    }
    
    func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata {
        guard let key = using.key else {
            throw CryptoError.notValidPrivateKey
        }
        
        let encryptedKey = try AES.KeyWrap.wrap(
            .init(data: cek),
            using: .init(data: key)
        )

        return .init(
            encryptedKey: encryptedKey,
            initializationVector: nil,
            authenticationTag: nil,
            pbs2saltInput: nil,
            pbs2saltCount: nil,
            otherMetadata: [:]
        )
    }
}
