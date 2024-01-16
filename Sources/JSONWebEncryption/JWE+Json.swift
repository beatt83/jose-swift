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
import JSONWebKey
import Tools

public typealias DefaultJWEJson = JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl>

/// `JWEJson` represents a JSON Web Encryption (JWE) object in JSON format, with customizable header types.
/// - Type parameters:
///   - P: A type conforming to `JWERegisteredFieldsHeader` used for the protected header.
///   - U: A type conforming to `JWERegisteredFieldsHeader` used for the shared protected header.
///   - R: A type conforming to `JWERegisteredFieldsHeader` used for the recipient-specific header.
public struct JWEJson<
    P: JWERegisteredFieldsHeader,
    U: JWERegisteredFieldsHeader,
    R: JWERegisteredFieldsHeader
> {
    
    /// `Recipient` represents a recipient in a JWE JSON object, containing header and key information.
    public struct Recipient {
        /// The recipient-specific header.
        let header: R?
        
        /// The raw data of the recipient-specific header.
        let headerData: Data?
        
        /// The encrypted key for the recipient.
        let encryptedKey: Data?
        
        /// Initializes a recipient with header data and an encrypted key.
        /// - Parameters:
        ///   - headerData: The raw data of the recipient-specific header.
        ///   - encryptedKey: The encrypted key.
        /// - Throws: Errors during the decoding of the recipient-specific header.
        init(
            headerData: Data? = nil,
            encryptedKey: Data? = nil
        ) throws {
            self.header = try headerData.map { try JSONDecoder().decode(R.self, from: $0) }
            self.headerData = headerData
            self.encryptedKey = encryptedKey
        }
        
        /// Initializes a recipient with a header object and an encrypted key.
        /// - Parameters:
        ///   - header: The recipient-specific header.
        ///   - encryptedKey: The encrypted key.
        /// - Throws: Errors during the encoding of the recipient-specific header.
        init(
            header: R? = nil,
            encryptedKey: Data? = nil
        ) throws {
            self.header = header
            self.headerData = try header.map { try JSONEncoder.jose.encode($0) }
            self.encryptedKey = encryptedKey
        }
        
        public func getKid() throws -> String {
            guard let kid = header?.keyID else {
                throw JWE.JWEError.missingKid
            }
            return kid
        }
    }
    
    /// The protected header.
    public let protected: P?
    
    /// The raw data of the protected header.
    public let protectedData: Data?
    
    /// The shared protected header.
    public let sharedProtected: U?
    
    /// The raw data of the shared protected header.
    public let sharedProtectedData: Data?
    
    /// The list of recipients of the JWE.
    public let recipients: [Recipient]
    
    /// The encrypted content (cipher text).
    public let cipherText: Data
    
    /// Additional authenticated data.
    public let addtionalAuthenticatedData: Data?
    
    /// The initialization vector used in the encryption algorithm.
    public let initializationVector: Data?
    
    /// The authentication tag verifying the integrity of the encrypted content.
    public let authenticationTag: Data?
    
    public func getKids() -> [String] {
        recipients.compactMap { try? $0.getKid() }
    }
}

extension JWEJson.Recipient: Codable {
    enum CodingKeys: String, CodingKey {
        case header
        case encryptedKey = "encrypted_key"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(header, forKey: .header)
        try encryptedKey.map { try container.encodeIfPresent(Base64URL.encode($0), forKey: .encryptedKey)}
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let header = try container.decodeIfPresent(R.self, forKey: .header)
        let headerData = try header.map { try JSONEncoder.jose.encode($0) }
        self.headerData = headerData
        self.header = header
        
        let encryptedKeyBase64 = try container.decodeIfPresent(String.self, forKey: .encryptedKey)
        encryptedKey = try encryptedKeyBase64.map { try Base64URL.decode($0) } ?? Data()
    }
}

extension JWEJson: Codable {
    enum CodingKeys: String, CodingKey {
        case protected
        case unprotected
        case recipients
        case ciphertext
        case initializationVector = "iv"
        case authenticationTag = "tag"
        case addtionalAuthenticatedData = "aad"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try protectedData.map { try container.encodeIfPresent(Base64URL.encode($0), forKey: .protected)}
        try container.encodeIfPresent(sharedProtected, forKey: .unprotected)
        try initializationVector.map { try container.encodeIfPresent(Base64URL.encode($0), forKey: .initializationVector)}
        try authenticationTag.map { try container.encodeIfPresent(Base64URL.encode($0), forKey: .authenticationTag)}
        try addtionalAuthenticatedData.map { try container.encodeIfPresent(Base64URL.encode($0), forKey: .addtionalAuthenticatedData)}
        try container.encodeIfPresent(recipients, forKey: .recipients)
        try container.encodeIfPresent(Base64URL.encode(cipherText), forKey: .ciphertext)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let protectedBase64 = try container.decodeIfPresent(String.self, forKey: .protected)
        let protectedData = try protectedBase64.map { try Base64URL.decode($0) }
        self.protectedData = protectedData
        self.protected = try protectedData.map { try JSONDecoder().decode(P.self, from: $0) }
        
        let unprotected = try container.decodeIfPresent(U.self, forKey: .unprotected)
        let unprotectedData = try unprotected.map { try JSONEncoder.jose.encode($0) }
        self.sharedProtectedData = unprotectedData
        self.sharedProtected = unprotected
        
        let ivBase64 = try container.decodeIfPresent(String.self, forKey: .initializationVector)
        self.initializationVector = try ivBase64.map { try Base64URL.decode($0) }
        
        let tagBase64 = try container.decodeIfPresent(String.self, forKey: .authenticationTag)
        self.authenticationTag = try tagBase64.map { try Base64URL.decode($0) }
        
        let cipherBase64 = try container.decode(String.self, forKey: .ciphertext)
        self.cipherText = try Base64URL.decode(cipherBase64)
        
        let aadBase64 = try container.decodeIfPresent(String.self, forKey: .addtionalAuthenticatedData)
        self.addtionalAuthenticatedData = try aadBase64.map { try Base64URL.decode($0) }
        
        self.recipients = try container.decodeIfPresent([Recipient].self, forKey: .recipients) ?? []
    }
}
