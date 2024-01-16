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
import JSONWebAlgorithms

/// `JWEEncryptionProvider` represents an encryption provider for JSON Web Encryption (JWE) with a specific algorithm family.
public struct JWEEncryptionProvider: Hashable {
    /// The family of key management algorithm.
    public let family: KeyManagementAlgorithm.Family
    
    /// Encryptor conforming to the specified key management algorithm family.
    let encryptor: JWEEncryptor
    
    /// Decryptor conforming to the specified key management algorithm family.
    let decryptor: JWEDecryptor
    
    /// Initializes a new encryption provider with specified algorithm family, encryptor, and decryptor.
    /// - Parameters:
    ///   - family: The family of key management algorithms.
    ///   - encryptor: The encryptor instance.
    ///   - decryptor: The decryptor instance.
    public init(
        family: KeyManagementAlgorithm.Family,
        encryptor: JWEEncryptor,
        decryptor: JWEDecryptor
    ) {
        self.family = family
        self.encryptor = encryptor
        self.decryptor = decryptor
    }
    
    /// Determines if the provider supports a given key management algorithm.
    /// - Parameter alg: The key management algorithm to check.
    /// - Returns: `true` if the provider supports the algorithm, otherwise `false`.
    public func supportsKeyAlgorithm(_ alg: KeyManagementAlgorithm) -> Bool {
        alg.family == family
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(family.rawValue)
    }
    
    public static func == (lhs: JWEEncryptionProvider, rhs: JWEEncryptionProvider) -> Bool {
        lhs.family == rhs.family
    }
}

/// `JWEEncryptionModule` manages a collection of `JWEEncryptionProvider` instances and provides encryption and decryption functionalities.
public struct JWEEncryptionModule {
    /// A set of registered encryption providers.
    public let registeredEncryptions: Set<JWEEncryptionProvider>
    
    /// Multi-encryptor for handling multiple encryption operations.
    public let multiEncryptor: JWEMultiEncryptor
    
    /// Multi-decryptor for handling multiple decryption operations.
    public let multiDecryptor: JWEMultiDecryptor
    
    /// Returns an encryptor for a given key management algorithm.
    /// - Parameter alg: The key management algorithm.
    /// - Throws: `JWE.JWEError.unsupportedEncryption` if no encryptor supports the algorithm.
    /// - Returns: The corresponding `JWEEncryptor`.
    func encryptor(alg: KeyManagementAlgorithm) throws -> JWEEncryptor {
        guard
            let provider = registeredEncryptions.first(where: { $0.supportsKeyAlgorithm(alg) })
        else {
            throw JWE.JWEError.unsupportedEncryption(alg: alg)
        }
        return provider.encryptor
    }
    
    /// Returns a decryptor for a given key management algorithm.
    /// - Parameter alg: The key management algorithm.
    /// - Throws: `JWE.JWEError.unsupportedEncryption` if no decryptor supports the algorithm.
    /// - Returns: The corresponding `JWEDecryptor`.
    func decryptor(alg: KeyManagementAlgorithm) throws -> JWEDecryptor {
        guard
            let provider = registeredEncryptions.first(where: { $0.supportsKeyAlgorithm(alg) })
        else {
            throw JWE.JWEError.unsupportedEncryption(alg: alg)
        }
        return provider.decryptor
    }
}

extension JWEEncryptionModule {
    /// The default `JWEEncryptionModule` instance with a predefined set of encryption providers.
    public static var `default`: JWEEncryptionModule = .init(
        registeredEncryptions: Set(
            [
                .init(family: .aes, encryptor: AESJWEEncryptor(), decryptor: AESJWEDecryptor()),
                .init(family: .direct, encryptor: DirectJWEEncryptor(), decryptor: DirectJWEDecryptor()),
                .init(family: .ecdh1pu, encryptor: ECDH1PUJWEEncryptor(), decryptor: ECDH1PUJWEDecryptor()),
                .init(family: .ecdhes, encryptor: ECDHJWEEncryptor(), decryptor: ECDHJWEDecryptor()),
                .init(family: .rsa, encryptor: RSAJWEEncryptor(), decryptor: RSAJWEDecryptor()),
                .init(family: .aes, encryptor: AESJWEEncryptor(), decryptor: AESJWEDecryptor()),
            ]
        ),
        multiEncryptor: MultiEncryptor(),
        multiDecryptor: MultiDecryptor()
    )
}
