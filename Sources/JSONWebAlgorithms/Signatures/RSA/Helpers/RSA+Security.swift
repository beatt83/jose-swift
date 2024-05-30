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

import CryptoSwift
import Foundation
import Security

extension RSA {
    func getSecKey() throws -> SecKey {
        let raw = try externalRepresentation()
        let attributes: [String: Any] = [
          kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
          kSecAttrKeyClass as String: d != nil ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic,
          kSecAttrKeySizeInBits as String: keySize,
          kSecAttrIsPermanent as String: false
        ]
        var error:Unmanaged<CFError>? = nil
        guard let key = SecKeyCreateWithData(
            raw as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            let error = error?.takeUnretainedValue()
            throw CryptoError.securityLayerError(internalStatus: (error as? NSError)?.code, internalError: (error as? NSError))
        }
        return key
    }
}
