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
import JWK

struct PBES2SHAKeyWrapper {
    
    struct PBES2SHAResult {
        let encrypedKey: Data
        let input: Data
        let count: Int
    }
    
    static func encrypt(
        cek: Data,
        using: JWK,
        algorithmData: Data = Data(),
        input: Data? = nil,
        count: Int? = nil,
        variant: CryptoSwift.HMAC.Variant
    ) throws -> PBES2SHAResult {
        guard let key = using.key else {
            throw CryptoError.missingOctetSequenceKey
        }
        let input = try input ?? SecureRandom.secureRandomData(count: 8)
        let count = count ?? 1000
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
        let salt = Array(algorithmData) + [0x00] + input
        let derivedKey = try Data(PKCS5.PBKDF2(
            password: Array(key),
            salt: salt,
            iterations: count,
            keyLength: keyLength,
            variant: variant
        ).calculate())
        
        let encryptedKey = try AES.KeyWrap.wrap(
            .init(data: cek),
            using: .init(data: derivedKey)
        )
        
        return .init(
            encrypedKey: encryptedKey,
            input: input,
            count: count
        )
    }
    
    static func decrypt(
        encryptedKey: Data,
        using: JWK,
        algorithmData: Data = Data(),
        input: Data,
        count: Int,
        variant: CryptoSwift.HMAC.Variant
    ) throws -> Data {
        guard let key = using.key else {
            throw CryptoError.missingOctetSequenceKey
        }
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
        let salt = Array(algorithmData) + [0x00] + input
        let derivedKey = try Data(PKCS5.PBKDF2(
            password: Array(key),
            salt: salt,
            iterations: count,
            keyLength: keyLength,
            variant: variant
        ).calculate())
        
        let decrypted = try AES.KeyWrap.unwrap(
            encryptedKey,
            using: .init(data: derivedKey)
        )
        
        return decrypted.withUnsafeBytes { Data($0) }
    }
}
