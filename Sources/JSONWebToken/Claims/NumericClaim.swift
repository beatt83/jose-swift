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

/// Represents a numeric claim within a JWT.
public struct NumberClaim: Claim {
    public var value: ClaimElement
    
    /// Initializes a `NumberClaim` with a key and a numeric value.
    /// - Parameters:
    ///   - key: The key for the claim.
    ///   - value: The numeric value for the claim.
    public init<N: Numeric & Codable>(key: String, value: N) {
        self.value = ClaimElement(key: key, element: .codable(value))
    }
}
