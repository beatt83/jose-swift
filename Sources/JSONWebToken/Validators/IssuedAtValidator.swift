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

/// A validator that checks the 'iat' (issued at) claim in a JWT.
///
/// This validator ensures that the JWT's issued-at time is not in the future.
/// If the issued-at claim is missing and marked as required, a `JWT.JWTError.requiredClaimMissing("iat")` error is thrown.
/// If the issued-at time is later than the current date, a `JWT.JWTError.issuedInTheFuture` error is thrown.
public struct IssuedAtValidator: ClaimValidator, Sendable {
    /// Indicates whether the issued-at claim is required.
    public let required: Bool
    
    /// Creates an issued-at time validator.
    ///
    /// - Parameter required: A Boolean value indicating whether the issued-at claim is required. Defaults to `true`.
    public init(required: Bool = true) {
        self.required = required
    }
    
    /// Validates the issued-at claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("iat")` if the claim is missing when required,
    ///           or `JWT.JWTError.issuedInTheFuture` if the issued-at time is in the future.
    public func isValid(_ jwtString: String) throws {
        guard let iat = try? JWT.getIssuedAt(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("iat")
            }
            return
        }
        let currentDate = Date()
        guard iat <= currentDate else {
            throw JWT.JWTError.issuedInTheFuture
        }
    }
}
