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

import JSONWebAlgorithms
import JSONWebSignature

/// A validator that checks the header alg is properly set and is not one of the black listed algorithms in a JWT (only available for Signature JWTs).
///
/// This validator verifies that the JWT's header alg contains is set and not a black listed `SigningAlgorithm`.
/// If the header algorithm is missing, a `JWT.JWTError.algorithmIsRequired` error is thrown.
/// If the JWT's header algorithm is one of the black listed, a `JWT.JWTError.algorithmIsBlackListed(algorithm:)` error is thrown.
public struct SigningAlgorithmBlackListValidator: ClaimValidator, Sendable {
    /// Indicates whether the header requires an algorithm set.
    public let required: Bool
    let blackListAlgorithms: Set<SigningAlgorithm>

    /// Creates an algorithm validator with an array of black listed algorithms.
    ///
    /// - Parameters:
    ///    - blackList: A set of `SigningAlgorithms` that should are not permitted.
    ///    - algorithmRequired: A Boolean value indicating whether the header requires an algorithm set. Defaults to `true`.
    public init(blackList: [SigningAlgorithm], algorithmRequired: Bool = true) {
        self.required = algorithmRequired
        self.blackListAlgorithms = Set(blackList)
    }
    
    /// Validates the header algorithm in the provided JWT string. (Encrypted JWTs will ignore this validator)
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `throw JWT.JWTError.algorithmIsRequired` if the header alg is missing when required,
    ///           or `JWT.JWTError.algorithmIsBlackListed` if the algorithm is black listed.
    public func isValid(_ jwtString: String) throws {
        guard case JWT.Format.jws = try JWT.jwtFormat(jwtString: jwtString) else {
            return
        }
        guard
            let header: DefaultJWSHeaderImpl = try? JWT.getHeader(jwtString: jwtString),
            let algorithm = header.algorithm
        else {
            if required {
                throw JWT.JWTError.algorithmIsRequired
            }
            return
        }

        guard !blackListAlgorithms.contains(algorithm) else {
            throw JWT.JWTError.algorithmIsBlackListed(algorithm: algorithm)
        }
    }
}
