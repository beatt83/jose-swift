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

/// A validator that checks the 'nbf' (not before) claim in a JWT.
///
/// This validator ensures that the JWT is not used before the specified not-before time.
/// If the not-before claim is missing and marked as required, a `JWT.JWTError.requiredClaimMissing("nbf")` error is thrown.
/// If the current date is earlier than the not-before time, a `JWT.JWTError.notYetValid` error is thrown.
public struct NotBeforeTimeValidator: ClaimValidator, Sendable {
    /// Indicates whether the not-before claim is required.
    public let required: Bool
    
    /// Creates a not-before time validator.
    ///
    /// - Parameter required: A Boolean value indicating whether the not-before claim is required. Defaults to `true`.
    public init(required: Bool = true) {
        self.required = required
    }
    
    /// Validates the not-before time claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("nbf")` if the claim is missing when required,
    ///           or `JWT.JWTError.notYetValid` if the JWT is used before the allowed time.
    public func isValid(_ jwtString: String) throws {
        guard let nbf = try? JWT.getNotBeforeTime(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("nbf")
            }
            return
        }
        let currentDate = Date()
        guard currentDate >= nbf else {
            throw JWT.JWTError.notYetValid
        }
    }
}
