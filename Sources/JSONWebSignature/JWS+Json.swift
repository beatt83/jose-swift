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

public typealias DefaultJWSJson = JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>

/// `JWSJson` represents a JSON Web Signature (JWS) object with support for multiple signatures.
/// It is a generic struct allowing custom types for the protected and unprotected headers.
///
/// - Parameters:
///   - P: The type of the protected header, conforming to `JWSRegisteredFieldsHeader`.
///   - H: The type of the unprotected header, conforming to `JWSRegisteredFieldsHeader`.
public struct JWSJson<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader> {
    
    /// `Signature` represents a single signature within the `JWSJson`, including its associated headers and signature data.
    public struct Signature {
        /// Raw data of the protected header. This header is encoded and included in the JWS signature calculation.
        public let protectedHeaderData: Data?

        /// An instance of the protected header. Contains metadata about the signature and, optionally, the payload.
        /// It provides structured access to the header fields when available.
        public let protectedHeader: P?

        /// Raw data of the unprotected header. This header is not included in the JWS signature calculation.
        /// It's typically used for storing header fields that do not need to be integrity-protected.
        public let unprotectedHeaderData: Data?

        /// An instance of the unprotected header. Contains additional metadata that is not included in the signature.
        /// Similar to `protectedHeader`, it provides structured access to the header fields.
        public let unprotectedHeader: H?

        /// The signature data. This is the cryptographic result of signing the payload along with the protected header.
        public let signature: Data
        
        /// Initializes a new `Signature` instance with optional header data and signature.
        /// - Parameters:
        ///   - protectedData: The raw data of the protected header.
        ///   - protected: The protected header instance.
        ///   - headerData: The raw data of the unprotected header.
        ///   - header: The unprotected header instance.
        ///   - signature: The signature data.
        /// - Throws: An error if encoding the headers fails.
        public init(
            protectedData: Data? = nil,
            protected: P?,
            headerData: Data? = nil,
            header: H?,
            signature: Data
        ) throws {
            self.protectedHeaderData = try protectedData ?? protected.map { try JSONEncoder.jose.encode($0) }
            self.protectedHeader = protected
            self.unprotectedHeaderData = try headerData ?? header.map { try JSONEncoder.jose.encode($0) }
            self.unprotectedHeader = header
            self.signature = signature
        }
        
        /// Retrieves the Key ID (`kid`) from the headers.
        /// - Throws: `JWS.JWSError.missingKid` if both protected and unprotected headers are missing the `kid`.
        /// - Returns: The Key ID (`kid`) if available.
        public func getKid() throws -> String {
            guard let protectedKid = protectedHeader?.keyID else {
                guard let headerKid = unprotectedHeader?.keyID else {
                    throw JWS.JWSError.missingKid
                }
                return headerKid
            }
            return protectedKid
        }
        
        /// Constructs a `JWS` instance from the signature and payload.
        /// - Parameter payload: The payload data to be included in the `JWS`.
        /// - Throws: An error if the `JWS` initialization fails.
        /// - Returns: A `JWS` instance.
        public func jws(payload: Data) throws -> JWS {
            try JWS.init(
                protectedHeaderData: protectedHeaderData ?? Data(),
                data: payload, 
                signature: signature
            )
        }
        
        /// Validates and returns the algorithm used in the headers.
        /// - Throws: `JWS.JWSError.missingAlgorithm` if both protected and unprotected headers are missing the algorithm.
        /// - Returns: The signing algorithm if available.
        func validateAlg() throws -> SigningAlgorithm? {
            guard let protectedAlg = protectedHeader?.algorithm else {
                guard let headerAlg = unprotectedHeader?.algorithm else {
                    throw JWS.JWSError.missingAlgorithm
                }
                return headerAlg
            }
            return protectedAlg
        }
    }
    
    /// The payload data of the `JWSJson`.
    public let payload: Data
    
    /// An array of `Signature` instances representing each signature in the `JWSJson`.
    public let signatures: [Signature]
    
    /// Retrieves all Key IDs (`kid`) from the signatures.
    /// - Returns: An array of Key IDs (`kid`).
    public func getKids() -> [String] {
        signatures.compactMap { try? $0.getKid() }
    }
    
    /// Converts the `JWSJson` into a flattened format.
    /// - Throws: An error if the flattening process fails.
    /// - Returns: A `JWSJsonFlattened` instance.
    public func flattened() throws -> JWSJsonFlattened<P, H> {
        try .init(fullJson: self)
    }
    
    /// Filters and finds the signatures that match a given `JWK`.
    /// - Parameter jwk: The `JWK` used for filtering.
    /// - Returns: An array of `Signature` instances that match the given `JWK`.
    func findSignaturesForJWK(jwk: JWK) -> [Signature] {
        signatures.filter {
            let result = (
            try? jwk.keyID == $0.getKid()
            || jwk.algorithm == $0.validateAlg()?.rawValue
        ) ?? false
            return result
        }
    }
}

extension JWSJson: Codable {
    enum CodingKeys: String, CodingKey {
        case payload
        case signatures
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Base64URL.encode(payload), forKey: .payload)
        try container.encode(signatures, forKey: .signatures)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let payloadBase64 = try container.decode(String.self, forKey: .payload)
        self.payload = try Base64URL.decode(payloadBase64)
        self.signatures = try container.decode([Signature].self, forKey: .signatures)
    }
}


extension JWSJson.Signature: Codable {
    enum CodingKeys: String, CodingKey {
        case protected
        case signature
        case header
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(protectedHeaderData.map { Base64URL.encode($0) }, forKey: .protected)
        try container.encodeIfPresent(Base64URL.encode(signature), forKey: .signature)
        try container.encodeIfPresent(unprotectedHeader, forKey: .header)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let protectedBase64 = try container.decodeIfPresent(String.self, forKey: .protected)
        let protectedData = try protectedBase64.map { try Base64URL.decode($0) }
        self.protectedHeaderData = protectedData
        self.protectedHeader = try protectedData.map { try JSONDecoder().decode(P.self, from: $0) }
        
        let signatureBase64 = try container.decodeIfPresent(String.self, forKey: .signature)
        signature = try signatureBase64.map { try Base64URL.decode($0) } ?? Data()
        
        let header = try container.decodeIfPresent(H.self, forKey: .header)
        self.unprotectedHeaderData = try header.map { try JSONEncoder.jose.encode($0) }
        self.unprotectedHeader = header
    }
}
