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

struct AESGCM {
    
    static func encrypt(
        payload: Data,
        cek: Data,
        initializationVector: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> (cipher: Data, authenticationData: Data) {
        let sealedBox = try AES.GCM.seal(
            payload,
            using: .init(data: cek),
            nonce: .init(data: initializationVector),
            authenticating: additionalAuthenticatedData
        )
        return (sealedBox.ciphertext, sealedBox.tag)
    }
    
    static func decrypt(
        cipher: Data,
        using: Data,
        initializationVector: Data = Data(),
        authenticationTag: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> Data {
        return try AES.GCM.open(
            .init(
                nonce: .init(data: initializationVector),
                ciphertext: cipher,
                tag: authenticationTag
            ),
            using: .init(data: using),
            authenticating: additionalAuthenticatedData
        )
    }
}
