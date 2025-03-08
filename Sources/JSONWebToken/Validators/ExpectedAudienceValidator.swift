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

/// A validator that checks the 'aud' (audience) claim in a JWT.
///
/// This validator verifies that the JWT's audience claim contains the expected audience(s).
/// If the audience claim is missing and marked as required, a `JWT.JWTError.requiredClaimMissing("iss")` error is thrown.
/// If the JWT's audience does not include the expected audience(s), a `JWT.JWTError.audienceMismatch` error is thrown.
public struct ExpectedAudienceValidator: ClaimValidator, Sendable {
    /// Indicates whether the audience claim is required.
    public let required: Bool
    /// The expected audience values.
    let expectedAudience: [String]

    /// Creates an audience validator with an array of expected audience values.
    ///
    /// - Parameters:
    ///   - expectedAudience: An array of expected audience values.
    ///   - required: A Boolean value indicating whether the audience claim is required. Defaults to `true`.
    public init(expectedAudience: [String], required: Bool = true) {
        self.expectedAudience = expectedAudience
        self.required = required
    }
    
    /// Creates an audience validator with a single expected audience value.
    ///
    /// - Parameters:
    ///   - expectedAudience: The expected audience value.
    ///   - required: A Boolean value indicating whether the audience claim is required. Defaults to `true`.
    public init(expectedAudience: String, required: Bool = true) {
        self.expectedAudience = [expectedAudience]
        self.required = required
    }
    
    /// Validates the audience claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("iss")` if the claim is missing when required,
    ///           or `JWT.JWTError.audienceMismatch` if the expected audience is not present.
    public func isValid(_ jwtString: String) throws {
        guard let aud = try? JWT.getAudience(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("iss")
            }
            return
        }
        guard Set(aud).isSuperset(of: expectedAudience) else {
            throw JWT.JWTError.audienceMismatch
        }
    }
}
