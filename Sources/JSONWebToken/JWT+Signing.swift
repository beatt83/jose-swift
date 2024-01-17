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
    static func signed<P: JWSRegisteredFieldsHeader>(
        payload: C,
        protectedHeader: P,
        key: JWK
    ) throws -> JWT {
        JWT(
            payload: payload,
            format: .jws(try JWS(
                header: protectedHeader,
                data: JSONEncoder.jose.encode(payload),
                key: key
            ))
        )
    }
    
    /// Signs a JWT string as a nested JWT in JWS format.
    ///
    /// This method is used for creating a nested JWT, where the payload is another JWT string.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be signed.
    ///   - protectedHeader: A `JWSRegisteredFieldsHeader` containing header fields that will be protected in the JWS.
    ///   - key: The `JWK` used for signing the JWT string.
    /// - Returns: A string representing the signed JWT in JWS format.
    /// - Throws: An error if the signing process fails.
    static func signedAsNested<P: JWSRegisteredFieldsHeader>(
        jwtString: String,
        protectedHeader: P,
        key: JWK
    ) throws -> String {
        var protectedHeader = protectedHeader
        protectedHeader.contentType = "JWT"
        
        return try JWS(
            header: protectedHeader,
            data: JSONEncoder.jose.encode(jwtString.tryToData()),
            key: key
        ).compactSerialization
    }
}
