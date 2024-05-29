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

/// Represents an object claim within a JWT.
public struct ObjectClaim: Claim {
    let isRoot: Bool
    public var value: ClaimElement
    
    /// A result builder for constructing object claims.
    @resultBuilder
    public struct ObjectClaimBuilder {
        /// Builds an array of `Claim` from the provided components.
        /// - Parameter components: The claims to include in the object.
        /// - Returns: An array of `Claim`.
        public static func buildBlock(_ components: Claim...) -> [Claim] {
            components
        }
    }
    
    /// Initializes an `ObjectClaim` with a key and a builder for the object elements.
    /// - Parameters:
    ///   - key: The key for the claim.
    ///   - claims: A closure that returns an array of `Claim` using the result builder.
    public init(key: String, @ObjectClaimBuilder claims: () -> [Claim]) {
        self.isRoot = false
        self.value = .init(key: key, element: .object(claims().map(\.value)))
    }
    
    init(key: String, claims: [ClaimElement]) {
        self.isRoot = false
        self.value = .init(key: key, element: .object(claims))
    }
    
    init(root: Bool, claims: [ClaimElement]) {
        self.isRoot = root
        self.value = .init(key: "", element: .object(claims))
    }
}
