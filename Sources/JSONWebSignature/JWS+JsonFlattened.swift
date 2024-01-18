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

import JSONWebAlgorithms
import JSONWebKey
import Foundation
import Tools

/// `JWSJsonFlattened` represents a JSON Web Signature (JWS) object in a flattened JSON format.
/// It is a generic struct allowing custom types for the protected and unprotected headers.
///
/// - Parameters:
///   - P: The type of the protected header, conforming to `JWSRegisteredFieldsHeader`.
///   - H: The type of the unprotected header, conforming to `JWSRegisteredFieldsHeader`.
public struct JWSJsonFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader> {
    /// Represents the payload of the JWS. This is the data that was signed.
    public let payload: Data

    /// Raw data of the protected header. This header is encoded and included in the JWS signature calculation.
    public let protectedHeaderData: Data?

    /// An instance of the protected header. Contains metadata about the signature and, optionally, the payload.
    public let protectedHeader: P?

    /// Raw data of the unprotected header. This header is not included in the JWS signature calculation.
    public let unprotectedHeaderData: Data?

    /// An instance of the unprotected header. Contains additional metadata that is not included in the signature.
    public let unprotectedHeader: H?

    /// The signature data. This is the result of signing the payload and the protected header.
    public let signature: Data

    /// Base64URL encoded representation of the payload.
    public var encodedPayload: String {
        Base64URL.encode(payload)
    }

    /// Base64URL encoded representation of the protected header data. Returns `nil` if `protectedHeaderData` is `nil`.
    public var encodedProtectedHeader: String? {
        protectedHeaderData.map { Base64URL.encode($0) }
    }

    /// Base64URL encoded representation of the unprotected header data. Returns `nil` if `unprotectedHeaderData` is `nil`.
    public var encodedHeader: String? {
        unprotectedHeaderData.map { Base64URL.encode($0) }
    }

    /// Base64URL encoded representation of the signature.
    public var encodedSignature: String {
        Base64URL.encode(signature)
    }
    
    /// Initializes a new `JWSJsonFlattened` instance.
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedData: The raw data of the protected header.
    ///   - protected: The protected header instance.
    ///   - headerData: The raw data of the unprotected header.
    ///   - header: The unprotected header instance.
    ///   - signature: The signature data.
    public init(
        payload: Data,
        protectedData: Data?,
        protected: P?,
        headerData: Data?,
        header: H?,
        signature: Data
    ) {
        self.payload = payload
        self.protectedHeaderData = protectedData
        self.protectedHeader = protected
        self.unprotectedHeaderData = headerData
        self.unprotectedHeader = header
        self.signature = signature
    }
    
    public init(fullJson: JWSJson<P, H>) throws {
        guard
            fullJson.signatures.count == 1,
            let signature = fullJson.signatures.first
        else {
            throw JWS.JWSError.multipleSignaturesCantBeFlattened
        }
        
        self.payload = fullJson.payload
        self.unprotectedHeader = signature.unprotectedHeader
        self.unprotectedHeaderData = signature.unprotectedHeaderData
        self.protectedHeader = signature.protectedHeader
        self.protectedHeaderData = signature.protectedHeaderData
        self.signature = signature.signature
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
    
    /// Constructs a `JWS` instance from the flattened structure.
    /// - Throws: An error if the `JWS` initialization fails.
    /// - Returns: A `JWS` instance.
    public func jws() throws -> JWS {
        try JWS.init(
            protectedHeaderData: protectedHeaderData ?? Data(),
            data: payload,
            signature: signature
        )
    }
    
    /// Converts the `JWSJsonFlattened` into a full `JWSJson` format.
    /// - Throws: An error if the conversion process fails.
    /// - Returns: A `JWSJson` object.
    public func fullJson() throws -> JWSJson<P, H> {
        try .init(
            payload: payload,
            signatures: [
                .init(
                    protectedData: protectedHeaderData,
                    protected: protectedHeader,
                    headerData: unprotectedHeaderData,
                    header: unprotectedHeader,
                    signature: signature
                )
            ]
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

extension JWSJsonFlattened: Codable {
    enum CodingKeys: String, CodingKey {
        case protected
        case signature
        case header
        case payload
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(protectedHeaderData.map { Base64URL.encode($0) }, forKey: .protected)
        try container.encodeIfPresent(Base64URL.encode(signature), forKey: .signature)
        try container.encodeIfPresent(unprotectedHeader, forKey: .header)
        try container.encode(Base64URL.encode(payload), forKey: .payload)
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
        
        let payloadBase64 = try container.decode(String.self, forKey: .payload)
        self.payload = try Base64URL.decode(payloadBase64)
    }
}
