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
import JWK
import Tools

struct AESKeyUnwrap: KeyUnwrapping {
    func contentKeyDecrypt(
        encryptedKey: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> Data {
        guard let key = using.key else {
            throw CryptoError.missingOctetSequenceKey
        }

        return try AES.KeyWrap.unwrap(
            encryptedKey,
            using: .init(data: key)
        ).withUnsafeBytes { Data($0) }
    }
}
