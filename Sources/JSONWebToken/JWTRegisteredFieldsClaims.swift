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

/// `JWTRegisteredFieldsClaims` is a protocol defining the standard claims typically included in a JWT.
/// Conforming types can represent the payload of a JWT, encompassing both registered claim names and custom claims.
public protocol JWTRegisteredFieldsClaims {
    // "iss" claim representing the issuer of the JWT.
    var iss: String? { get }
    // "sub" claim representing the subject of the JWT.
    var sub: String? { get }
    // "aud" claim representing the audience(s) of the JWT.
    var aud: [String]? { get }
    // "exp" claim representing the expiration time of the JWT.
    var exp: Date? { get }
    // "nbf" claim representing the time before which the JWT must not be accepted.
    var nbf: Date? { get }
    // "iat" claim representing the time at which the JWT was issued.
    var iat: Date? { get }
    // "jti" claim representing a unique identifier for the JWT.
    var jti: String? { get }
}

/// `DefaultJWTClaimsImpl` is a struct implementing the `JWTRegisteredFieldsClaims` protocol, providing a default set of claims.
public struct DefaultJWTClaimsImpl: JWTRegisteredFieldsClaims, Codable {
    public let iss: String?
    public let sub: String?
    public let aud: [String]?
    public let exp: Date?
    public let nbf: Date?
    public let iat: Date?
    public let jti: String?
    
    /// Initializes a new `DefaultJWTClaimsImpl` instance with optional parameters for each standard claim.
    public init(
        iss: String? = nil,
        sub: String? = nil,
        aud: [String]? = nil,
        exp: Date? = nil,
        nbf: Date? = nil,
        iat: Date? = nil,
        jti: String? = nil
    ) {
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.exp = exp
        self.nbf = nbf
        self.iat = iat
        self.jti = jti
    }
}
