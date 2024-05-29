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

indirect enum Value {
    case codable(Codable)
    case element(ClaimElement)
    case array([ClaimElement])
    case object([ClaimElement])
}

/// Represents a claim element used within JWTs.
public struct ClaimElement {
    var key: String
    var element: Value
    
    init(key: String, element: Value) {
        self.key = key
        self.element = element
    }
    
    /// Initializes a `ClaimElement` with a codable value.
    /// - Parameters:
    ///   - key: The key for the claim.
    ///   - value: The codable value of the claim.
    public init<C: Codable>(key: String, value: C) {
        self.key = key
        self.element = .codable(value)
    }
}

/// Protocol representing a claim within a JWT.
public protocol Claim {
    var value: ClaimElement { get }
}

/// Protocol representing a registered claim within a JWT.
public protocol JWTRegisteredClaim: Claim {
    var value: ClaimElement { get }
}
