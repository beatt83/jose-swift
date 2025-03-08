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

/// A protocol for validating a specific claim within a JWT.
/// Conforming types implement logic to verify that a claim in the provided JWT string meets expected criteria.
public protocol ClaimValidator {
    /// Indicates whether the claim is required.
    var required: Bool { get }
    
    /// Validates the claim in the provided JWT string.
    ///
    /// - Parameter jwtString: The JWT string containing the claim to be validated.
    /// - Throws: An error if the claim is missing (when required) or does not meet the validation criteria.
    func isValid(_ jwtString: String) throws
}
