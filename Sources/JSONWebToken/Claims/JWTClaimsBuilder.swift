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

/// A result builder for constructing JWT claims.
@resultBuilder
public struct JWTClaimsBuilder {
    /// Builds a claim from the provided components.
    /// - Parameter components: The claims to include.
    /// - Returns: An `ObjectClaim` containing the provided claims.
    public static func buildBlock(_ components: Claim...) -> Claim {
        ObjectClaim(root: true, claims: components.map(\.value))
    }
    
    /// Builds a claim using a closure with the result builder.
    /// - Parameter builder: A closure that returns a claim.
    /// - Returns: A claim built by the closure.
    /// - Throws: Rethrows any error thrown within the builder closure.
    public static func build(@JWTClaimsBuilder builder: () throws -> Claim) rethrows -> Claim  {
        try builder()
    }
}

extension Value {
    func getValue<T>() -> T? {
        switch self {
        case .codable(let value):
            return value as? T
        default:
            return nil
        }
    }
}

extension ObjectClaim: JWTRegisteredFieldsClaims {
    var objectClaims: [ClaimElement] {
        switch value.element {
        case .object(let array):
            return array
        default:
            return []
        }
    }
    
    public var iss: String? {
        objectClaims.first { $0.key == "iss" }?.element.getValue()
    }
    
    public var sub: String? {
        objectClaims.first { $0.key == "sub" }?.element.getValue()
    }
    
    public var aud: [String]? {
        objectClaims.first { $0.key == "aud" }?.element.getValue()
    }
    
    public var exp: Date? {
        objectClaims.first { $0.key == "exp" }?.element.getValue()
    }
    
    public var nbf: Date? {
        objectClaims.first { $0.key == "nbf" }?.element.getValue()
    }
    
    public var iat: Date? {
        objectClaims.first { $0.key == "iat" }?.element.getValue()
    }
    
    public var jti: String? {
        objectClaims.first { $0.key == "jti" }?.element.getValue()
    }
    
    public func validateExtraClaims() throws {}
}
