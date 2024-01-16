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

struct AES256GCM: ContentEncryptor, ContentDecryptor {
    
    let contentEncryptionAlgorithm: String = ContentEncryptionAlgorithm.a256GCM.rawValue
    let initializationVectorSizeInBits: Int = ContentEncryptionAlgorithm.a256GCM.initializationVectorSizeInBits
    let cekKeySize: Int = ContentEncryptionAlgorithm.a256GCM.keySizeInBits
    
    func generateInitializationVector() throws -> Data {
        try SecureRandom.secureRandomData(count: initializationVectorSizeInBits)
    }
    
    func generateCEK() throws -> Data {
        try SecureRandom.secureRandomData(count: cekKeySize / 8)
    }
    
    func encrypt(
        payload: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> ContentEncryptionResult {
        let (cipher, tag) = try AESGCM.encrypt(
            payload: payload,
            cek: key,
            initializationVector: arguments.initializationVector ?? generateInitializationVector(),
            additionalAuthenticatedData: arguments.additionalAuthenticationData ?? Data()
        )
        return .init(cipher: cipher, authenticationData: tag)
    }
    
    func decrypt(
        cipher: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> Data {
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard let tag = arguments.authenticationTag else {
            throw CryptoError.missingAuthenticationTag
        }
        
        guard let aad = arguments.additionalAuthenticationData else {
            throw CryptoError.missingAdditionalAuthenticatingData
        }
        
        return try AESGCM.decrypt(
            cipher: cipher,
            using: key,
            initializationVector: iv,
            authenticationTag: tag,
            additionalAuthenticatedData: aad
        )
    }
}
