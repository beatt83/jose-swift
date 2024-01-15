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

struct AESCBC_SHA512: ContentEncryptor, ContentDecryptor {
    
    let contentEncryptionAlgorithm: String = ContentEncryptionAlgorithm.a256CBCHS512.rawValue
    let initializationVectorSizeInBits: Int = ContentEncryptionAlgorithm.a256CBCHS512.initializationVectorSizeInBits
    let cekKeySize: Int = ContentEncryptionAlgorithm.a256CBCHS512.keySizeInBits
    
    func generateInitializationVector() throws -> Data {
        try SecureRandom.secureRandomData(count: initializationVectorSizeInBits / 8)
    }
    
    func generateCEK() throws -> Data {
        try SecureRandom.secureRandomData(count: cekKeySize / 8)
    }
    
    func encrypt(
        payload: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> ContentEncryptionResult {
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard iv.count * 8 == initializationVectorSizeInBits else {
            throw CryptoError.initializationVectorWrongSize(sizeInBits: initializationVectorSizeInBits)
        }
        
        guard let aad = arguments.additionalAuthenticationData else {
            throw CryptoError.missingAdditionalAuthenticatingData
        }
        
        let (cipher, tag) = try AESCBC_SHA<SHA512>.encrypt(
            payload: payload,
            cek: key,
            authenticationTagLength: 32,
            initializationVector: iv,
            additionalAuthenticatedData: aad
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
        
        return try AESCBC_SHA<SHA512>.decrypt(
            cipher: cipher,
            cek: key,
            authenticationTagLength: 32,
            initializationVector: iv,
            additionalAuthenticatedData: aad,
            authenticationTag: tag
        )
    }
}
