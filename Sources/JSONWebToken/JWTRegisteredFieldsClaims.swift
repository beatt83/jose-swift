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

typealias DefaultJWT = JWT<DefaultJWTClaimsImpl>

/// `JWTRegisteredFieldsClaims` is a protocol defining the standard claims typically included in a JWT.
/// Conforming types can represent the payload of a JWT, encompassing both registered claim names and custom claims.
public protocol JWTRegisteredFieldsClaims: Codable {
    // "iss" claim representing the issuer of the JWT.
    var issuer: String? { get }
    // "sub" claim representing the subject of the JWT.
    var subject: String? { get }
    // "aud" claim representing the audience(s) of the JWT.
    var audience: [String]? { get }
    // "exp" claim representing the expiration time of the JWT.
    var expirationTime: Date? { get }
    // "nbf" claim representing the time before which the JWT must not be accepted.
    var notBeforeTime: Date? { get }
    // "iat" claim representing the time at which the JWT was issued.
    var issuedAt: Date? { get }
    // "jti" claim representing a unique identifier for the JWT.
    var jwtID: String? { get }

    /// Validates extra claims in the JWT.
    /// - Throws: `JWTError` if any claim validations fail.
    func validateExtraClaims() throws
}

/// `DefaultJWTClaimsImpl` is a struct implementing the `JWTRegisteredFieldsClaims` protocol, providing a default set of claims.
public struct DefaultJWTClaimsImpl: JWTRegisteredFieldsClaims {
    public let issuer: String?
    public let subject: String?
    public let audience: [String]?
    public let expirationTime: Date?
    public let notBeforeTime: Date?
    public let issuedAt: Date?
    public let jwtID: String?
    
    /// Initializes a new `DefaultJWTClaimsImpl` instance with optional parameters for each standard claim.
    public init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: [String]? = nil,
        expirationTime: Date? = nil,
        notBeforeTime: Date? = nil,
        issuedAt: Date? = nil,
        jwtID: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expirationTime = expirationTime
        self.notBeforeTime = notBeforeTime
        self.issuedAt = issuedAt
        self.jwtID = jwtID
    }
    
    public func validateExtraClaims() throws {}
}
