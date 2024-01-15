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

import JWA
import JWK
import Foundation
import Tools

struct JWSJsonFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader> {
    let payload: Data
    let protectedData: Data?
    let protected: P?
    let headerData: Data?
    let header: H?
    let signature: Data
    
    init(
        payload: Data,
        protectedData: Data?,
        protected: P?,
        headerData: Data?,
        header: H?,
        signature: Data
    ) {
        self.payload = payload
        self.protectedData = protectedData
        self.protected = protected
        self.headerData = headerData
        self.header = header
        self.signature = signature
    }
    
    init(fullJson: JWSJson<P, H>) throws {
        guard
            fullJson.signatures.count == 1,
            let signature = fullJson.signatures.first
        else {
            throw JWS.JWSError.multipleSignaturesCantBeFlattened
        }
        
        self.payload = fullJson.payload
        self.header = signature.header
        self.headerData = signature.headerData
        self.protected = signature.protected
        self.protectedData = signature.protectedData
        self.signature = signature.signature
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
    
    func jws() throws -> JWS {
        try JWS.init(header: protectedData ?? Data(), data: payload, signature: signature)
    }
    
    func fullJson() throws -> JWSJson<P, H> {
        try .init(
            payload: payload,
            signatures: [
                .init(
                    protectedData: protectedData,
                    protected: protected,
                    headerData: headerData,
                    header: header,
                    signature: signature
                )
            ]
        )
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
        try container.encodeIfPresent(protectedData.map { Base64URL.encode($0) }, forKey: .protected)
        try container.encodeIfPresent(Base64URL.encode(signature), forKey: .signature)
        try container.encodeIfPresent(header, forKey: .header)
        try container.encode(Base64URL.encode(payload), forKey: .payload)
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
        
        let payloadBase64 = try container.decode(String.self, forKey: .payload)
        self.payload = try Base64URL.decode(payloadBase64)
    }
}
