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
        print("payload: \(Base64URL.encode(payload))")
        print("initializationVector: \(Base64URL.encode(initializationVector))")
        print("additionalAuthenticatedData: \(Base64URL.encode(additionalAuthenticatedData))")
        print("cek: \(Base64URL.encode(cek))")
        let sealedBox = try AES.GCM.seal(
            payload,
            using: .init(data: cek),
            nonce: .init(data: initializationVector),
            authenticating: additionalAuthenticatedData
        )
        print("tag: \(Base64URL.encode(sealedBox.tag))")
        return (sealedBox.ciphertext, sealedBox.tag)
    }
    
    static func decrypt(
        cipher: Data,
        using: Data,
        initializationVector: Data = Data(),
        authenticationTag: Data = Data(),
        additionalAuthenticatedData: Data = Data()
    ) throws -> Data {
        print("cipher: \(Base64URL.encode(cipher))")
        print("initializationVector: \(Base64URL.encode(initializationVector))")
        print("additionalAuthenticatedData: \(Base64URL.encode(additionalAuthenticatedData))")
        print("tag: \(Base64URL.encode(authenticationTag))")
        print("cek: \(Base64URL.encode(using))")
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
