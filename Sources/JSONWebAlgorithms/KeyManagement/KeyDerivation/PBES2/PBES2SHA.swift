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
import CryptoSwift
import Foundation
import JSONWebKey

struct PBES2SHAKeyDerivation {
    
    struct PBES2SHAResult {
        let derivedKey: Data
        let input: Data
        let count: Int
    }
    
    static func derive(
        password: Data,
        saltInput: Data,
        saltCount: Int,
        variant: CryptoSwift.HMAC.Variant
    ) throws -> PBES2SHAResult {
        let keyLength: Int
        switch variant {
        case .sha2(.sha256):
            keyLength = 16
        case .sha2(.sha384):
            keyLength = 24
        case .sha2(.sha512):
            keyLength = 32
        default:
            throw CryptoError.unavailablePBES2ShaVariant
        }
        let derivedKey = try Data(PKCS5.PBKDF2(
            password: password.bytes,
            salt: saltInput.bytes,
            iterations: saltCount,
            keyLength: keyLength,
            variant: variant
        ).calculate())
        
        return .init(
            derivedKey: derivedKey,
            input: saltInput,
            count: saltCount
        )
    }
}
