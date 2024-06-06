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

import CommonCrypto
import Foundation

/// `CryptoError` is an enumeration representing various errors that can occur in cryptographic operations.
public enum CryptoError: LocalizedError {
    /// Error indicating that the initialization vector is missing for an operation that requires it.
    case missingInitializationVector

    /// Error indicating that the authentication tag is missing for an operation that requires it.
    case missingAuthenticationTag

    /// Error indicating that additional authenticated data is missing for an operation that requires it.
    case missingAdditionalAuthenticatingData

    /// Error indicating that the octet sequence key is missing.
    case missingOctetSequenceKey

    /// Error indicating that the PBES2 salt input or salt count is missing for PBES2 operations.
    case missingPBS2SaltInputOrCount

    /// Error indicating that the size of the initialization vector is incorrect.
    /// - Parameter sizeInBits: The size of the IV in bits.
    case initializationVectorWrongSize(sizeInBits: Int)

    /// Error indicating that decryption failed because the authentication tag does not match.
    case decryptionFailedAuthenticationTagDoesntMatch

    /// Error indicating that unwrapping of an RSA key failed.
    case failedRSAKeyUnwrap

    /// Error indicating that a specified SHA variant for PBES2 is not available or unsupported.
    case unavailablePBES2ShaVariant

    /// Error indicating that an RSA key is invalid.
    case invalidRSAKey

    /// Error indicating that the provided key is not a valid private key.
    case notValidPrivateKey

    /// Error indicating that the provided key is not a valid public key.
    case notValidPublicKey

    /// Error indicating that the specified algorithm is not supported.
    /// - Parameter alg: The algorithm that is not supported.
    case algorithmNotSupported(alg: String)

    /// Error related to the underlying security layer, potentially including an internal status and error.
    /// - Parameters:
    ///   - internalStatus: Optional internal status code.
    ///   - internalError: Optional internal error.
    case securityLayerError(internalStatus: Int?, internalError: Error?)

    /// Error indicating that a signature is invalid.
    case invalidSignature

    /// Error indicating that required arguments are missing for an operation.
    /// - Parameter arguments: The names of the missing arguments.
    case missingArguments([String])

    /// Error indicating that key generation is not possible for the specified type and curve.
    /// - Parameters:
    ///   - type: The key type.
    ///   - curve: Optional curve name, if applicable.
    case cannotGenerateKeyForTypeAndCurve(type: String, curve: String?)
    
    case keyFormatNotSupported(format: String, supportedFormats: [String])
    
    case commonCryptoError(status: CCStatus)
}
