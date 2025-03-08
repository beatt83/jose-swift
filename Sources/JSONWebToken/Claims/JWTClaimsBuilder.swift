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
    public typealias PartialResult = [any Claim]

    public static func buildExpression(_ expression: any Claim) -> PartialResult {
        [expression]
    }

    public static func buildExpression(_ expression: PartialResult) -> PartialResult {
        expression
    }

    public static func buildBlock(_ components: PartialResult...) -> PartialResult {
        components.flatMap { $0 }
    }
    
    public static func buildBlock(_ component: PartialResult) -> PartialResult {
        component
    }

    public static func buildOptional(_ component: PartialResult?) -> PartialResult {
        component ?? []
    }

    public static func buildEither(first component: PartialResult) -> PartialResult {
        component
    }

    public static func buildEither(second component: PartialResult) -> PartialResult {
        component
    }
    
    public static func buildEmpty() -> PartialResult {
        []
    }

    public static func buildFinalResult(_ components: PartialResult) -> ObjectClaim {
        ObjectClaim(root: true, claims: components.map(\.value))
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
}
