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

extension JWT {
    /// `JWTError` is an enumeration representing various errors that can occur while processing JSON Web Tokens (JWTs).
    enum JWTError: LocalizedError {
        /// General error case when something goes wrong but the exact reason is unspecified or unknown.
        case somethingWentWrong

        /// Error indicating that the sender's key is missing. This is typically required for operations like signing or key agreement.
        case missingSenderKey
        
        /// Error indicating that a key required for verifying a nested JWT is missing.
        /// This error is thrown when the necessary key for a nested JWT layer is not provided,
        /// making it impossible to verify the integrity or authenticity of the nested JWT.
        case missingNestedJWTKey

        /// Error indicating that the signature of the JWT is invalid. This can occur during verification if the signature does not match the payload or is malformed.
        case invalidSignature

        /// Error indicating a mismatch between the expected issuer (`iss` claim) and the actual issuer of the JWT.
        case issuerMismatch

        /// Error indicating that the JWT has expired (`exp` claim) and is no longer valid.
        case expired

        /// Error indicating that the JWT is not yet valid (`nbf` claim) as the current time is before the specified not-before time.
        case notYetValid

        /// Error indicating that the JWT's issue time (`iat` claim) is set in the future, which is an invalid condition.
        case issuedInTheFuture

        /// Error indicating a mismatch between the expected audience (`aud` claim) and the actual audience of the JWT.
        case audienceMismatch
    }
}
