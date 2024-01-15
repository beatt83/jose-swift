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
import JWA
import JWK
import Tools

struct JWSJson<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>: Codable {
    
    struct Signature {
        let protectedData: Data?
        let protected: P?
        let headerData: Data?
        let header: H?
        let signature: Data
        
        init(
            protectedData: Data? = nil,
            protected: P?,
            headerData: Data? = nil,
            header: H?,
            signature: Data
        ) throws {
            self.protectedData = try protectedData ?? protected.map { try JSONEncoder.jose.encode($0) }
            self.protected = protected
            self.headerData = try headerData ?? header.map { try JSONEncoder.jose.encode($0) }
            self.header = header
            self.signature = signature
        }
        
        func validateAlg() throws -> SigningAlgorithm? {
            guard let protectedAlg = protected?.algorithm else {
                guard let headerAlg = header?.algorithm else {
                    throw JWS.JWSError.missingAlgorithm
                }
                return headerAlg
            }
            return protectedAlg
        }
        
        func getKid() throws -> String {
            guard let protectedKid = protected?.keyID else {
                guard let headerKid = header?.keyID else {
                    throw JWS.JWSError.missingKid
                }
                return headerKid
            }
            return protectedKid
        }
        
        func jws(payload: Data) throws -> JWS {
            try JWS.init(header: protectedData ?? Data(), data: payload, signature: signature)
        }
    }
    
    let payload: Data
    let signatures: [Signature]
    
    func findSignaturesForJWK(jwk: JWK) -> [Signature] {
        signatures.filter {
            let result = (
            try? jwk.keyID == $0.getKid()
            || jwk.algorithm == $0.validateAlg()?.rawValue
        ) ?? false
            return result
        }
    }
    
    func flattened() throws -> JWSJsonFlattened<P, H> {
        try .init(fullJson: self)
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
        try container.encodeIfPresent(protectedData.map { Base64URL.encode($0) }, forKey: .protected)
        try container.encodeIfPresent(Base64URL.encode(signature), forKey: .signature)
        try container.encodeIfPresent(header, forKey: .header)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let protectedBase64 = try container.decodeIfPresent(String.self, forKey: .protected)
        let protectedData = try protectedBase64.map { try Base64URL.decode($0) }
        self.protectedData = protectedData
        self.protected = try protectedData.map { try JSONDecoder().decode(P.self, from: $0) }
        
        let signatureBase64 = try container.decodeIfPresent(String.self, forKey: .signature)
        signature = try signatureBase64.map { try Base64URL.decode($0) } ?? Data()
        
        let header = try container.decodeIfPresent(H.self, forKey: .header)
        self.headerData = try header.map { try JSONEncoder.jose.encode($0) }
        self.header = header
    }
}
