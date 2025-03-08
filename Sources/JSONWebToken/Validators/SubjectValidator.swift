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

/// A validator that checks the 'sub' (subject) claim in a JWT.
///
/// This validator verifies that the JWT's subject matches an expected value. If the subject claim is missing
/// and marked as required, a `JWT.JWTError.requiredClaimMissing("sub")` error is thrown.
/// If the subject does not match the expected value, a `JWT.JWTError.subjectMismatch` error is thrown.
public struct SubjectValidator: ClaimValidator, Sendable {
    /// Indicates whether the subject claim is required.
    public let required: Bool
    /// The expected subject value.
    let expectedSubject: String
    
    /// Creates a subject validator with the expected subject.
    ///
    /// - Parameters:
    ///   - expectedSubject: The expected subject value.
    ///   - required: A Boolean value indicating whether the subject claim is required. Defaults to `true`.
    public init(expectedSubject: String, required: Bool = true) {
        self.expectedSubject = expectedSubject
        self.required = required
    }
    
    /// Validates the subject claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: `JWT.JWTError.requiredClaimMissing("sub")` if the claim is missing when required,
    ///           or `JWT.JWTError.subjectMismatch` if the subject does not match the expected value.
    public func isValid(_ jwtString: String) throws {
        guard let subject = try? JWT.getSubject(jwtString: jwtString) else {
            if required {
                throw JWT.JWTError.requiredClaimMissing("sub")
            }
            return
        }
        if subject != expectedSubject {
            throw JWT.JWTError.subjectMismatch
        }
    }
}
