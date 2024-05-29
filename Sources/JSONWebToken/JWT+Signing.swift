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
import JSONWebKey
import JSONWebSignature

extension JWT {
    /// Creates a signed JWT using the provided payload, header, and key.
    ///
    /// This method signs the payload and creates a JWT in JWS (JSON Web Signature) format.
    ///
    /// - Parameters:
    ///   - payload: The payload to be included in the JWT, conforming to `JWTRegisteredFieldsClaims`.
    ///   - protectedHeader: A `JWSRegisteredFieldsHeader` containing header fields that will be protected in the JWS.
    ///   - key: The `JWK` (JSON Web Key) used for signing the payload.
    /// - Returns: A `JWT` instance in JWS format with the signed payload.
    /// - Throws: An error if the signing process fails.
    public static func signed<P: JWSRegisteredFieldsHeader>(
        payload: Codable,
        protectedHeader: P,
        key: JWK?
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        protectedHeader.type = "JWT"
        let encodedPayload = try JSONEncoder.jwt.encode(payload)
        return JWT(
            payload: encodedPayload,
            format: .jws(try JWS(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                key: key
            ))
        )
    }
    
    public static func signed<P: JWSRegisteredFieldsHeader>(
        @JWTClaimsBuilder payload: () -> Claim,
        protectedHeader: P,
        key: JWK?
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        protectedHeader.type = "JWT"
        let encodedPayload = try JSONEncoder.jwt.encode(payload().value)
        return JWT(
            payload: encodedPayload,
            format: .jws(try JWS(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                key: key
            ))
        )
    }
    
    /// Signs a JWT payload as a nested JWT in JWS format with distinct inner and outer JWS headers.
    ///
    /// This method creates a nested JWS structure where the payload is first signed using the inner header and key,
    /// then the resulting JWT string is signed again using the outer header and key.
    ///
    /// - Parameters:
    ///   - payload: The payload to be signed, conforming to `JWTRegisteredFieldsClaims`.
    ///   - protectedHeader: A `JWSRegisteredFieldsHeader` containing header fields for the outer JWS layer.
    ///   - key: The `JWK` used for signing the outer JWT string.
    ///   - nestedProtectedHeader: A `JWSRegisteredFieldsHeader` containing header fields for the inner JWS layer.
    ///   - nestedKey: The `JWK` used for signing the inner JWT payload.
    /// - Returns: A `JWS` instance representing the doubly signed nested JWT.
    /// - Throws: An error if the signing process fails.
    public static func signedAsNested<
        P: JWSRegisteredFieldsHeader,
        NP: JWSRegisteredFieldsHeader
    >(
        payload: Codable,
        protectedHeader: P,
        key: JWK?,
        nestedProtectedHeader: NP,
        nestedKey: JWK?
    ) throws -> JWS {
        let jwt = try signed(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            key: nestedKey
        )
        
        return try signedAsNested(
            jwtString: jwt.jwtString,
            protectedHeader: protectedHeader,
            key: key
        )
    }
    
    public static func signedAsNested<
        P: JWSRegisteredFieldsHeader,
        NP: JWSRegisteredFieldsHeader
    >(
        @JWTClaimsBuilder payload: () -> Claim,
        protectedHeader: P,
        key: JWK?,
        nestedProtectedHeader: NP,
        nestedKey: JWK?
    ) throws -> JWS {
        let jwt = try signed(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            key: nestedKey
        )
        
        return try signedAsNested(
            jwtString: jwt.jwtString,
            protectedHeader: protectedHeader,
            key: key
        )
    }
    
    /// Signs a JWT string as a nested JWT in JWS format.
    ///
    /// This method is used for creating a nested JWT, where the payload is another JWT string.
    /// It signs the provided JWT string and wraps it in a new JWS structure.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be signed.
    ///   - protectedHeader: A `JWSRegisteredFieldsHeader` containing header fields that will be protected in the JWS.
    ///   - key: The `JWK` used for signing the JWT string.
    /// - Returns: A string representing the signed JWT in JWS format.
    /// - Throws: An error if the signing process fails.
    public static func signedAsNested<P: JWSRegisteredFieldsHeader>(
        jwtString: String,
        protectedHeader: P,
        key: JWK?
    ) throws -> JWS {
        var protectedHeader = protectedHeader
        protectedHeader.contentType = "JWT"
        
        return try JWS(
            payload: JSONEncoder.jwt.encode(jwtString.tryToData()),
            protectedHeader: protectedHeader,
            key: key
        )
    }
}
