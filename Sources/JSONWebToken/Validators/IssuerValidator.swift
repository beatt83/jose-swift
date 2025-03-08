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

/// A validator that checks the 'iss' (issuer) claim in a JWT.
///
/// This validator verifies that the JWT's issuer matches an expected value. If the issuer claim is missing
/// and marked as required, a `JWT.JWTError.requiredClaimMissing("iss")` error is thrown.
/// If the issuer does not match the expected value, a `JWT.JWTError.issuerMismatch` error is thrown.
public struct IssuerValidator: ClaimValidator, Sendable {
    /// Indicates whether the issuer claim is required.
    public let required: Bool
    /// The expected issuer value.
    let expectedIssuer: String
    
    /// Creates an issuer validator with the expected issuer.
    ///
    /// - Parameters:
    ///   - expectedIssuer: The expected issuer value.
    ///   - required: A Boolean value indicating whether the issuer claim is required. Defaults to `true`.
    public init(expectedIssuer: String, required: Bool = true) {
        self.expectedIssuer = expectedIssuer
        self.required = required
    }
    
    /// Validates the issuer claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("iss")` if the claim is missing when required,
    ///           or `JWT.JWTError.issuerMismatch` if the issuer does not match the expected value.
    public func isValid(_ jwtString: String) throws {
        guard let issuer = try? JWT.getIssuer(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("iss")
            }
            return
        }
        if issuer != expectedIssuer {
            throw JWT.JWTError.issuerMismatch
        }
    }
}
