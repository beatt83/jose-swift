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

/// A type alias for `JWTIdentifierClaim`.
typealias JtiClaim = JWTIdentifierClaim

/// Represents the "jti" (JWT ID) claim in a JWT.
public struct JWTIdentifierClaim: JWTRegisteredClaim {
    public var value: ClaimElement
    
    /// Initializes a `JWTIdentifierClaim` with a string value.
    /// - Parameter value: The JWT ID value for the claim.
    public init(value: String) {
        self.value = ClaimElement(key: "jti", element: .codable(value))
    }
}
