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

/// Represents an array claim within a JWT.
public struct ArrayClaim: Claim {
    public var value: ClaimElement
    
    /// A result builder for constructing array claims.
    @resultBuilder
    public struct ArrayClaimBuilder {
        /// Builds an array of `ArrayElementClaim` from the provided components.
        /// - Parameter components: The array element claims to include in the array.
        /// - Returns: An array of `ArrayElementClaim`.
        public static func buildBlock(_ components: ArrayElementClaim...) -> [ArrayElementClaim] {
            components
        }
        
        /// Builds an array of `ArrayElementClaim` from the provided components.
        /// - Parameter components: The array element claims to include in the array.
        /// - Returns: An array of `ArrayElementClaim`.
        public static func buildBlock(_ components: Claim...) -> [Claim] {
            components
        }
        
        /// Builds an array of `StringClaim` from the provided components.
        /// - Parameter components: The string claims to include in the array.
        /// - Returns: An array of `StringClaim`.
        public static func buildBlock(_ components: StringClaim...) -> [StringClaim] {
            components
        }
    }
    
    /// Initializes an `ArrayClaim` with a key and a builder for the array elements.
    /// - Parameters:
    ///   - key: The key for the claim.
    ///   - claims: A closure that returns an array of `ArrayElementClaim` using the result builder.
    public init(key: String, @ArrayClaimBuilder claims: () -> [ArrayElementClaim]) {
        self.value = .init(key: key, element: .array(claims().map(\.value)))
    }
    
    /// Initializes an `ArrayClaim` with a key and a builder for the array elements.
    /// - Parameters:
    ///   - key: The key for the claim.
    ///   - claims: A closure that returns an array of `Claim` using the result builder.
    public init(key: String, @ArrayClaimBuilder claims: () -> [Claim]) {
        self.value = .init(key: key, element: .array(claims().map(\.value)))
    }
}

/// Represents an element within an array claim.
public struct ArrayElementClaim {
    let value: ClaimElement
    
    /// Creates an `ArrayElementClaim` with a string value.
    /// - Parameter str: The string value for the claim.
    /// - Returns: An `ArrayElementClaim` containing the string value.
    public static func string(_ str: String) -> ArrayElementClaim {
        .init(value: StringClaim(key: "", value: str).value)
    }
    
    /// Creates an `ArrayElementClaim` with a numeric value.
    /// - Parameter number: The numeric value for the claim.
    /// - Returns: An `ArrayElementClaim` containing the numeric value.
    public static func number<N: Numeric & Codable>(_ number: N) -> ArrayElementClaim {
        .init(value: NumberClaim(key: "", value: number).value)
    }
    
    /// Creates an `ArrayElementClaim` with a boolean value.
    /// - Parameter boolean: The boolean value for the claim.
    /// - Returns: An `ArrayElementClaim` containing the boolean value.
    public static func bool(_ boolean: Bool) -> ArrayElementClaim {
        .init(value: BoolClaim(key: "", value: boolean).value)
    }
    
    /// Creates an `ArrayElementClaim` with an array of claims.
    /// - Parameter claims: A closure that returns an array of `ArrayElementClaim` using the result builder.
    /// - Returns: An `ArrayElementClaim` containing the array of claims.
    public static func array(@ArrayClaim.ArrayClaimBuilder claims: () -> [ArrayElementClaim]) -> ArrayElementClaim {
        .init(value: ArrayClaim(key: "", claims: claims).value)
    }
    
    /// Creates an `ArrayElementClaim` with an object of claims.
    /// - Parameter claims: A closure that returns an array of `Claim` using the result builder.
    /// - Returns: An `ArrayElementClaim` containing the object of claims.
    public static func object(@ObjectClaim.ObjectClaimBuilder claims: () -> [Claim]) -> ArrayElementClaim {
        .init(value: ObjectClaim(key: "", claims: claims).value)
    }
}
