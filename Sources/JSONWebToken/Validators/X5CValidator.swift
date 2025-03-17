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
import X509
import JSONWebKey
import JSONWebSignature

/// A validator that checks the 'x5c' (x509CertificateChain) header parameter in a JWT.
///
/// This validator is responsible for verifying that the JWT's certificate chain is valid, supports P256, P384, P521, secp256k1, Ed25519 and RSA.
/// It conforms to [RFC 7515 Section 4.1.6](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6), which
/// specifies the handling of the x5c header parameter. If the x5c header parameter is missing when required,
/// an error is thrown. This struct uses a semaphore to bridge asynchronous verification into synchronous code.
/// - Warning: This struct uses a semaphore to wait for an asynchronous task to complete, effectively turning
///   an asynchronous operation into a synchronous one. This may block the current thread during execution,
///   so avoid using it on the main thread. Where possible, consider using an asynchronous approach to fully
///   leverage Swift's concurrency model.
public struct X5CValidator<Policy: VerifierPolicy>: ClaimValidator, Sendable {
    
    /// A helper payload type for extracting the signing time from the JWT.
    struct SignedDatePayload: Decodable {
        let signedDate: Date
    }
    
    /// Indicates whether the x509CertificateChain header parameter is required in the JWT.
    public let required: Bool
    
    /// The trusted certificate store constructed from the provided root certificates.
    let trustedStore: CertificateStore
    
    /// A result builder closure that produces a concrete `VerifierPolicy` used for certificate validation.
    @PolicyBuilder
    let policy: @Sendable () throws -> Policy
    
    /// Creates an x5c validator with the expected trusted chain of certificates.
    ///
    /// - Parameters:
    ///   - rootCertificates: An array of root certificates to be used as the trusted chain.
    ///   - required: A Boolean value indicating whether the x5c header parameter is required. Defaults to `true`.
    ///   - policy: A result builder closure that produces a `VerifierPolicy` used to validate the certificate chain.
    ///             The default policy is an instance of `RFC5280Policy` configured with the current date.
    /// - Throws: An error of type `JWT.JWTError.invalidX5CChainNoRootCertificates` if no root certificates are provided.
    public init(
        rootCertificates: [Certificate],
        required: Bool = true,
        @PolicyBuilder policy: @escaping @Sendable () throws -> Policy = { RFC5280Policy(validationTime: Date()) }
    ) {
        self.trustedStore = .init(rootCertificates)
        self.policy = policy
        self.required = required
    }
    
    /// Creates an x5c validator with the expected trusted chain of certificates provided as PEM-encoded strings.
    ///
    /// - Parameters:
    ///   - rootCertificates: An array of strings representing the PEM-encoded certificates.
    ///   - required: A Boolean value indicating whether the x5c header parameter is required. Defaults to `true`.
    ///   - policy: A result builder closure that produces a `VerifierPolicy` used to validate the certificate chain.
    ///             The default policy is an instance of `RFC5280Policy` configured with the current date.
    /// - Throws: An error if the conversion from PEM-encoded strings to `Certificate` fails,
    ///           or if no certificates are provided.
    public init(
        rootCertificates: [String],
        required: Bool = true,
        @PolicyBuilder policy: @escaping @Sendable () throws -> Policy = { RFC5280Policy(validationTime: Date()) }
    ) throws {
        guard !rootCertificates.isEmpty else {
            throw JWT.JWTError.invalidX5CChainNoRootCertificates
        }
        try self.init(
            rootCertificates: rootCertificates.map { try X509.Certificate(pemEncoded: $0) },
            required: required,
            policy: policy
        )
    }
    
    /// Validates the x5c certificate chain contained within the provided JWT string.
    ///
    /// This method performs the following steps:
    /// 1. Parses the JWT and extracts the x5c header parameter from either JWE or JWS formats.
    /// 2. Converts the base64-encoded certificate strings into `Certificate` objects.
    /// 3. Extracts the validation date from the JWT payload if available.
    /// 4. Calls an asynchronous certificate chain verification function, synchronizing it using a semaphore.
    /// 5. Verifies the JWT signature using the public key from the first certificate in the chain.
    ///
    /// - Parameter jwtString: The JWT string to validate.
    /// - Throws: An error if the x5c header is required but missing,
    ///           if any certificate in the chain is invalid,
    ///           or if the certificate chain fails verification.
    public func isValid(_ jwtString: String) throws {
        let jwt = try JWT(jwtString: jwtString)
        let x5c: [String]
        
        switch jwt.format {
        case .jwe(let value):
            x5c = value.protectedHeader.x509CertificateChain ?? []
        case .jws(let value):
            x5c = value.protectedHeader.x509CertificateChain ?? []
        }
        
        guard !x5c.isEmpty else {
            if required {
                throw JWT.JWTError.invalidX5CChainMissingX5CHeader
            }
            return
        }
        
        let certificateData = try x5c.map {
            guard let data = Data(base64Encoded: $0) else {
                throw JWT.JWTError.invalidX5CChainInvalidCertificate
            }
            return data
        }
        
        let certificates = try certificateData.map {
            try Certificate(derEncoded: [UInt8]($0))
        }
        
        let date: Date
        if let validationTimePayload: SignedDatePayload = try? JWT.getPayload(jwtString: jwtString) {
            date = validationTimePayload.signedDate
        } else {
            date = Date()
        }
        
        let result = try verify(
            trustedStore: trustedStore,
            certificates: certificates,
            policy: {
                try policy()
                RFC5280Policy(validationTime: date)
            }
        )
        
        if let result, case .couldNotValidate(let failures) = result {
            throw JWT.JWTError.invalidX5Chain(errors: failures.map(\.policyFailureReason.description))
        }
        
        let pemKey = try certificates[0].publicKey.serializeAsPEM().pemString
        let key = try JWK(pem: pemKey)
        _ = try JWT.verify(jwtString: jwt.jwtString, signerKey: key)
    }
    
    /// Verifies the certificate chain by invoking an asynchronous chain verification function in a synchronous manner.
    ///
    /// - Parameters:
    ///   - trustedStore: The certificate store containing trusted root certificates.
    ///   - certificates: An array of certificates extracted from the x5c header.
    ///   - policy: A closure that produces a `VerifierPolicy` used to verify the chain.
    /// - Returns: A `VerificationResult` if available, or `nil` if verification was not completed.
    /// - Throws: Any error encountered during verification.
    private func verify(
        trustedStore: CertificateStore,
        certificates: [Certificate],
        @PolicyBuilder policy: @escaping @Sendable () throws -> some VerifierPolicy
    ) throws -> VerificationResult? {
        nonisolated(unsafe) var result: VerificationResult?
        let semaphore = DispatchSemaphore(value: 0)
        Task {
            result = try await verifyChain(trustedStore: trustedStore, certificates: certificates, policy: policy)
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }
}

/// Asynchronously verifies the certificate chain using the provided trusted store and verification policy.
///
/// - Parameters:
///   - trustedStore: The trusted certificate store containing the root certificates.
///   - certificates: An array of certificates to be validated.
///   - policy: A closure that produces a `VerifierPolicy` used for chain verification.
/// - Returns: A `VerificationResult` indicating whether the certificate chain could be validated.
/// - Throws: Any error encountered during the asynchronous verification process.
private func verifyChain(
    trustedStore: CertificateStore,
    certificates: [Certificate],
    policy: () throws -> some VerifierPolicy
) async throws -> VerificationResult {
    let untrustedChain = CertificateStore(certificates)
    var verifier = try Verifier(rootCertificates: trustedStore, policy: policy)
    let result = await verifier.validate(
        leafCertificate: certificates[0],
        intermediates: untrustedChain
    )
    return result
}
