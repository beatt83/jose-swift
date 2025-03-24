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

extension JWS {
    /// `JWSError` enumerates the various errors that can occur when processing JSON Web Signatures (JWS).
    public enum JWSError: LocalizedError {
        /// Indicates a generic error where something went wrong but no specific information is available.
        case somethingWentWrong

        /// Represents an error where the JWS input string is invalid.
        case invalidString

        /// Indicates an unsupported algorithm error, optionally providing details about the key type, algorithm, or curve.
        case unsupportedAlgorithm(keyType: String? = nil, algorithm: String? = nil, curve: String? = nil)

        /// Indicates a missing curve error, typically in the context of elliptic curve cryptography.
        case missingCurve

        /// Indicates a mismatch between the algorithm specified in the key and the one specified in the JWS header.
        case keyAlgorithmAndHeaderAlgorithmAreNotEqual(header: String, key: String)

        /// Indicates a mismatch between the algorithm specified in the protected header and the header.
        case protectedHeaderAlgorithmAndHeaderAlgorithmAreNotEqual(header: String, protectedHeader: String)

        /// Represents an error where the necessary algorithm information is missing.
        case missingAlgorithm

        /// Indicates that the Key ID ('kid') is missing, which is often crucial for identifying the correct key for processing.
        case missingKid
        
        /// Represents an error where the necessary key information is missing.
        case missingKey

        /// Indicates that no signature with algorithm or kid that matches the provided JSON Web Key (JWK).
        case noSignatureForJWK(jwkAlg: String?, jwkKid: String?)

        /// Represents an error when multiple signatures cannot be flattened into a single signature.
        case multipleSignaturesCantBeFlattened

        /// Indicates a failure in decoding either the complete JSON or the flattened JSON structure.
        case couldNotDecodeCompleteJsonOrFlattened
        
        case customHeaderIsNotCorrectlyFormatted(error: Error)
    }
}
