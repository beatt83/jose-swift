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
import JSONWebSignature
import JSONWebEncryption
import JSONWebKey

/// `JWT` represents a JSON Web Token which is a compact, URL-safe means of representing claims to be transferred between two parties.
///
/// The `JWT` struct is generic over `C`, which must conform to the `JWTRegisteredFieldsClaims` protocol. This allows for flexibility in defining the set of claims a JWT can carry.
///
/// - Parameters:
///   - C: The type of claims the JWT carries. Must conform to `JWTRegisteredFieldsClaims`.
public struct JWT<C: JWTRegisteredFieldsClaims> {
    /// `Format` is an enumeration that defines the two possible formats for a JWT: JWE and JWS.
    public enum Format {
        /// JWE format, representing an encrypted JWT.
        case jwe(JWE)
        
        /// JWS format, representing a signed JWT.
        case jws(JWS)
    }
    
    /// The payload of the JWT, containing the claims.
    public let payload: C
    
    /// The format of the JWT, either JWE (encrypted) or JWS (signed).
    public let format: Format
    
    /// A computed property that returns the JWT in its compact string representation.
    /// If the JWT is in JWE format, it returns the compact serialization of the JWE.
    /// If in JWS format, it returns the compact serialization of the JWS.
    public var jwtString: String {
        switch format {
        case .jwe(let jwe):
            return jwe.compactSerialization()
        case .jws(let jws):
            return jws.compactSerialization
        }
    }
    
    public init(payload: C, format: Format) {
        self.payload = payload
        self.format = format
    }
    
    public init(jwtString: String) throws {
        self.payload = try Self.getPayload(jwtString: jwtString)
        self.format = try Self.jwtFormat(jwtString: jwtString)
    }
}

public extension JWT {
    static func getPayload<Payload: JWTRegisteredFieldsClaims>(jwtString: String) throws -> Payload {
        return try JSONDecoder.jwt.decode(Payload.self, from: getPayload(jwtString: jwtString))
    }
    
    static func getPayload(jwtString: String) throws -> Data {
        switch try jwtFormat(jwtString: jwtString) {
        case .jwe:
            throw JWTError.cannotRetrievePayloadFromJWE
        case .jws(let jws):
            return jws.payload
        }
    }
    
    static func getIssuer(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.iss
    }
    
    static func getSubject(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.sub
    }
    
    static func getNotBeforeTime(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.nbf
    }
    
    static func getExpirationTime(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.exp
    }
    
    static func getIssuedAt(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.iat
    }
    
    static func getID(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.jti
    }
    
    static func getAudience(jwtString: String) throws -> [String]? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.aud
    }
    
    static func getHeader(jwtString: String) throws -> Data {
        switch try jwtFormat(jwtString: jwtString) {
        case .jwe(let jwe):
            return jwe.protectedHeaderData
        case .jws(let jws):
            return jws.protectedHeaderData
        }
    }
    
    static func jwtFormat(jwtString: String) throws -> Format {
        let components = jwtString.components(separatedBy: ".")
        switch components.count {
        case 3:
            return try .jws(.init(jwsString: jwtString))
        case 5:
            return try .jwe(.init(compactString: jwtString))
        default:
            throw JWTError.somethingWentWrong
        }
    }
}
