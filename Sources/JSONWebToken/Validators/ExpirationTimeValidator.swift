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

/// A validator that checks the 'exp' (expiration time) claim in a JWT.
///
/// This validator ensures that the JWT has not expired. If the expiration claim is missing
/// and marked as required, a `JWT.JWTError.requiredClaimMissing("exp")` error is thrown.
/// If the current date is later than the expiration time, a `JWT.JWTError.expired` error is thrown.
public struct ExpirationTimeValidator: ClaimValidator, Sendable {
    /// Indicates whether the expiration time claim is required.
    public let required: Bool
    
    /// Creates an expiration time validator.
    ///
    /// - Parameter required: A Boolean value indicating whether the expiration claim is required. Defaults to `true`.
    public init(required: Bool = true) {
        self.required = required
    }
    
    /// Validates the expiration time claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("exp")` if the claim is missing when required,
    ///           or `JWT.JWTError.expired` if the JWT has expired.
    public func isValid(_ jwtString: String) throws {
        guard let exp = try? JWT.getExpirationTime(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("exp")
            }
            return
        }
        let currentDate = Date()
        guard currentDate < exp else {
            throw JWT.JWTError.expired
        }
    }
}
