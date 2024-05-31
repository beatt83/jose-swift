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

/// `JWT` represents a JSON Web Token (JWT) structure as defined in [RFC7519](https://tools.ietf.org/html/rfc7519).
public struct JWT {
    /// `Format` is an enumeration that defines the two possible formats for a JWT: JWE and JWS.
    public enum Format {
        /// JWE format, representing an encrypted JWT.
        case jwe(JWE)
        
        /// JWS format, representing a signed JWT.
        case jws(JWS)
    }
    
    /// The payload of the JWT, containing the claims.
    public let payload: Data
    
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
    
    /// Initializes a `JWT` with a payload and format.
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - format: The format of the JWT, either JWE or JWS.
    public init(payload: Data, format: Format) {
        self.payload = payload
        self.format = format
    }
    
    /// Initializes a `JWT` with a format and a builder for the payload.
    /// - Parameters:
    ///   - format: The format of the JWT, either JWE or JWS.
    ///   - payload: A closure that returns a `Claim` using the result builder.
    /// - Throws: An error if the encoding process fails.
    public init(format: Format, @JWTClaimsBuilder payload: () -> Claim) throws {
        self.payload = try JSONEncoder.jwt.encode(payload().value)
        self.format = format
    }
    
    /// Initializes a `JWT` from its compact string representation.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    public init(jwtString: String) throws {
        self.payload = try Self.getPayload(jwtString: jwtString)
        self.format = try Self.jwtFormat(jwtString: jwtString)
    }
}

public extension JWT {
    /// Retrieves the payload from a JWT string and decodes it to a specified type.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The decoded payload.
    static func getPayload<Payload: Decodable>(jwtString: String) throws -> Payload {
        return try JSONDecoder.jwt.decode(Payload.self, from: getPayload(jwtString: jwtString))
    }
    
    /// Retrieves the payload data from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails or if the JWT is in JWE format.
    /// - Returns: The payload data.
    static func getPayload(jwtString: String) throws -> Data {
        switch try jwtFormat(jwtString: jwtString) {
        case .jwe:
            throw JWTError.cannotRetrievePayloadFromJWE
        case .jws(let jws):
            return jws.payload
        }
    }
    
    /// Retrieves the issuer from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The issuer string, if present.
    static func getIssuer(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.iss
    }
    
    /// Retrieves the subject from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The subject string, if present.
    static func getSubject(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.sub
    }
    
    /// Retrieves the not-before time from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The not-before date, if present.
    static func getNotBeforeTime(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.nbf
    }
    
    /// Retrieves the expiration time from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The expiration date, if present.
    static func getExpirationTime(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.exp
    }
    
    /// Retrieves the issued-at time from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The issued-at date, if present.
    static func getIssuedAt(jwtString: String) throws -> Date? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.iat
    }
    
    /// Retrieves the JWT ID from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The JWT ID string, if present.
    static func getID(jwtString: String) throws -> String? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.jti
    }
    
    /// Retrieves the audience from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: An array of audience strings, if present.
    static func getAudience(jwtString: String) throws -> [String]? {
        let payload: DefaultJWTClaimsImpl = try getPayload(jwtString: jwtString)
        return payload.aud
    }
    
    /// Retrieves the header data from a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the decoding process fails.
    /// - Returns: The header data.
    static func getHeader(jwtString: String) throws -> Data {
        switch try jwtFormat(jwtString: jwtString) {
        case .jwe(let jwe):
            return jwe.protectedHeaderData
        case .jws(let jws):
            return jws.protectedHeaderData
        }
    }
    
    /// Determines the format of a JWT string.
    /// - Parameter jwtString: The compact string representation of the JWT.
    /// - Throws: An error if the format cannot be determined.
    /// - Returns: The format of the JWT.
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
