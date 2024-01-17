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

extension DefaultJWTClaims: Codable {
    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expirationTime = "exp"
        case notBeforeTime = "nbf"
        case issuedAt = "iat"
        case jwtID = "jti"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(issuer, forKey: .issuer)
        try container.encodeIfPresent(subject, forKey: .subject)
        try container.encodeIfPresent(audience, forKey: .audience)
        try container.encodeIfPresent(expirationTime, forKey: .expirationTime)
        try container.encodeIfPresent(notBeforeTime, forKey: .notBeforeTime)
        try container.encodeIfPresent(issuedAt, forKey: .issuedAt)
        try container.encodeIfPresent(jwtID, forKey: .jwtID)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        audience = try container.decodeIfPresent([String].self, forKey: .audience)
        expirationTime = try container.decodeIfPresent(Date.self, forKey: .expirationTime)
        notBeforeTime = try container.decodeIfPresent(Date.self, forKey: .notBeforeTime)
        issuedAt = try container.decodeIfPresent(Date.self, forKey: .issuedAt)
        jwtID = try container.decodeIfPresent(String.self, forKey: .jwtID)
    }
}
