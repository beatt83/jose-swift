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

/// A type alias for `NotBeforeClaim`.
public typealias NbfClaim = NotBeforeClaim

/// Represents the "nbf" (not before) claim in a JWT.
public struct NotBeforeClaim: JWTRegisteredClaim {
    public var value: ClaimElement
    
    /// Initializes a `NotBeforeClaim` with a date value.
    /// - Parameter value: The not before date value for the claim.
    public init(value: Date) {
        self.value = ClaimElement(key: "nbf", element: .codable(value))
    }
}
