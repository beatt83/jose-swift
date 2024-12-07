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
import JSONWebAlgorithms
import JSONWebKey

extension JWE {
    /// `JWEError` is an enumeration representing various errors that can occur during the JSON Web Encryption (JWE) processes.
    public enum JWEError: LocalizedError {
        /// Error indicating that decryption is not supported for the specified algorithms.
        /// - Parameters:
        ///   - alg: The key management algorithm used or attempted to be used.
        ///   - enc: The content encryption algorithm used or attempted to be used.
        ///   - supportedAlgs: The list of supported key management algorithms.
        ///   - supportedEnc: The list of supported content encryption algorithms.
        case decryptionNotSupported(
            alg: KeyManagementAlgorithm?,
            enc: ContentEncryptionAlgorithm?,
            supportedAlgs: [KeyManagementAlgorithm],
            supportedEnc: [ContentEncryptionAlgorithm]
        )

        /// Error indicating that encryption is not supported for the specified algorithms.
        /// - Parameters:
        ///   - alg: The key management algorithm used or attempted to be used.
        ///   - enc: The content encryption algorithm used or attempted to be used.
        ///   - supportedAlgs: The list of supported key management algorithms.
        ///   - supportedEnc: The list of supported content encryption algorithms.
        case encryptionNotSupported(
            alg: KeyManagementAlgorithm?,
            enc: ContentEncryptionAlgorithm?,
            supportedAlgs: [KeyManagementAlgorithm],
            supportedEnc: [ContentEncryptionAlgorithm]
        )
        
        /// Indicates that the Key ID ('kid') is missing, which is often crucial for identifying the correct key for processing.
        case missingKid

        /// Error indicating that the Content Encryption Key (CEK) is missing.
        case missingCek

        /// Error indicating that the Key Encryption Key (KEK) is missing.
        case missingKek

        /// Error indicating that the encrypted key component of JWE is missing.
        case missingEncryptedKey

        /// Error indicating that the Initialization Vector (IV) for content encryption is missing.
        case missingContentIV

        /// Error indicating that the Authentication Tag for content encryption is missing.
        case missingContentAuthenticationTag

        /// Error indicating that the Initialization Vector (IV) for the key encryption is missing.
        case missingKeyIV

        /// Error indicating that the Authentication Tag for the key encryption is missing.
        case missingKeyTag

        /// Error indicating that the recipient's key is missing.
        case missingRecipientKey

        /// Error indicating that the sender's key is missing.
        case missingSenderKey

        /// Error indicating that the key management algorithm is missing.
        case missingKeyAlgorithm

        /// Error indicating that the content encryption algorithm is missing.
        case missingContentEncryptionAlgorithm

        /// Error indicating that the ephemeral key (temporary key used in some key agreement protocols) is missing.
        case missingEphemeralKey
        
        /// Error indicating that the salt input is missing.
        case missingSaltInput
        
        /// Error indicating that the salt iteration count is missing.
        case missingSaltCount
        
        /// Error indicating that the salt count is not minimum recommended of 1000 interations.
        case invalidSaltCount
        
        /// Error indicating that the salt input as not minimum size of 8.
        case invalidSaltLength

        /// Error indicating that the JWE compact string is invalid or malformed.
        case invalidJWECompactString

        /// Error indicating that no recipients are provided for the JWE.
        case noRecipients

        /// Error indicating that a recipient cannot be found for a provided JSON Web Key (JWK).
        /// - Parameter jwk: The JWK for which a recipient cannot be found.
        case recipientCannotBeFoundFor(jwk: JWK)

        /// Error indicating that an internal wrapper is missing for a specified key management algorithm.
        /// - Parameter alg: The algorithm for which the wrapper is missing.
        case internalErrorWrapperMissingFor(alg: KeyManagementAlgorithm)

        /// Error indicating that an internal unwrapper is missing for a specified key management algorithm.
        /// - Parameter alg: The algorithm for which the unwrapper is missing.
        case internalErrorUnWrapperMissingFor(alg: KeyManagementAlgorithm)

        /// Error indicating that key agreement is not available for a specified algorithm.
        /// - Parameter alg: The algorithm for which the key agreement funcionality is missing.
        case internalErrorAgreementNotAvailableFor(alg: KeyManagementAlgorithm)

        /// Error indicating that key derivation is not available for a specified algorithm.
        /// - Parameter alg: The algorithm for which the key derivation funcionality is missing.
        case internalErrorDerivationNotAvailableFor(alg: KeyManagementAlgorithm)

        /// Error indicating that the operation is unsupported for the specified algorithm(s).
        /// - Parameters:
        ///   - alg: The key management algorithm used or attempted to be used.
        ///   - enc: The content encryption algorithm used or attempted to be used.
        case unsupportedOperation(alg: KeyManagementAlgorithm?, enc: ContentEncryptionAlgorithm?)

        /// Error indicating that the specified encryption algorithm is unsupported.
        /// - Parameters:
        ///   - alg: The key management algorithm used or attempted to be used.
        ///   - enc: The content encryption algorithm used or attempted to be used.
        case unsupportedEncryption(alg: KeyManagementAlgorithm)

        /// General error indicating that something went wrong in the JWE process, not covered by other error types.
        case somethingWentWrong
    }
}
