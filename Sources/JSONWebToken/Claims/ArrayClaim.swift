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
        public typealias ClaimPartialResult = [any Claim]
        public typealias ArrayClaimPartialResult = [ArrayElementClaim]
        public typealias StringClaimPartialResult = [StringClaim]
        /// Builds an array of `ArrayElementClaim` from the provided components.
        /// - Parameter components: The array element claims to include in the array.
        /// - Returns: An array of `ArrayElementClaim`.
        public static func buildBlock(_ components: ArrayClaimPartialResult...) -> ArrayClaimPartialResult {
            components.flatMap { $0 }
        }
        
        /// Builds an array of `ArrayElementClaim` from the provided components.
        /// - Parameter components: The array element claims to include in the array.
        /// - Returns: An array of `ArrayElementClaim`.
        public static func buildBlock(_ components: ClaimPartialResult...) -> ClaimPartialResult {
            components.flatMap { $0 }
        }
        
        /// Builds an array of `StringClaim` from the provided components.
        /// - Parameter components: The string claims to include in the array.
        /// - Returns: An array of `StringClaim`.
        public static func buildBlock(_ components: StringClaimPartialResult...) -> StringClaimPartialResult {
            components.flatMap { $0 }
        }
        
        public static func buildExpression(_ expression: any Claim) -> ClaimPartialResult {
            [expression]
        }
        
        public static func buildExpression(_ expression: ArrayElementClaim) -> ArrayClaimPartialResult {
            [expression]
        }
        
        public static func buildExpression(_ expression: StringClaim) -> StringClaimPartialResult {
            [expression]
        }
        
        /// Adds support for optionals
        public static func buildOptional(_ component:  ClaimPartialResult?) -> ClaimPartialResult {
            guard let component else {
                return []
            }
            return component
        }
        
        
        /// Adds support for if statements in build block
        public static func buildEither(first component: ClaimPartialResult) -> ClaimPartialResult {
            component
        }
        
        public static func buildEither(second component: ClaimPartialResult) -> ClaimPartialResult {
            component
        }
        
        /// Adds support for optionals
        public static func buildOptional(_ component:  ArrayClaimPartialResult?) -> ArrayClaimPartialResult {
            guard let component else {
                return []
            }
            return component
        }
        
        
        /// Adds support for if statements in build block
        public static func buildEither(first component: ArrayClaimPartialResult) -> ArrayClaimPartialResult {
            component
        }
        
        public static func buildEither(second component: ArrayClaimPartialResult) -> ArrayClaimPartialResult {
            component
        }
        
        /// Adds support for optionals
        public static func buildOptional(_ component:  StringClaimPartialResult?) -> StringClaimPartialResult {
            guard let component else {
                return []
            }
            return component
        }
        
        
        /// Adds support for if statements in build block
        public static func buildEither(first component: StringClaimPartialResult) -> StringClaimPartialResult {
            component
        }
        
        public static func buildEither(second component: StringClaimPartialResult) -> StringClaimPartialResult {
            component
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
