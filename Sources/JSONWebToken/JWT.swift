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
}
