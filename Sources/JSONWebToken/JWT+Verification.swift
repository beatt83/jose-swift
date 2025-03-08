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
import JSONWebEncryption
import JSONWebKey
import JSONWebSignature

extension JWT {
    
    /// An enumeration of validators for various JWT claims.
    ///
    /// Each case represents a specific validator used during JWT verification. Custom validators
    /// conforming to `ClaimValidator` can also be provided using the `.custom` case.
    public enum Validator {
        /// Validates the 'iss' (issuer) claim.
        case iss(expectedIssuer: String, required: Bool = true)
        /// Validates the 'sub' (subject) claim.
        case sub(expectedSubject: String, required: Bool = true)
        /// Validates the 'aud' (audience) claim.
        case aud(expectedAudience: [String], required: Bool = true)
        /// Validates the 'exp' (expiration time) claim.
        case exp(required: Bool = true)
        /// Validates the 'nbf' (not before) claim.
        case nbf(required: Bool = true)
        /// Validates the 'iat' (issued at) claim.
        case iat(required: Bool = true)
        /// Uses a custom validator conforming to `ClaimValidator`.
        case custom(ClaimValidator)
        
        /// A Boolean value indicating whether the validator is marked as required.
        var isRequired: Bool {
            switch self {
            case .iss(expectedIssuer: _, required: let required),
                 .sub(expectedSubject: _, required: let required),
                 .aud(expectedAudience: _, required: let required),
                 .exp(required: let required),
                 .nbf(required: let required),
                 .iat(required: let required):
                return required
            case .custom(let validator):
                return validator.required
            }
        }
        
        /// Returns the concrete `ClaimValidator` associated with the enum case.
        var validator: ClaimValidator {
            switch self {
            case .iss(let expectedIssuer, let required):
                return IssuerValidator(expectedIssuer: expectedIssuer, required: required)
            case .sub(let expectedSubject, let required):
                return SubjectValidator(expectedSubject: expectedSubject, required: required)
            case .aud(let expectedAudience, let required):
                return ExpectedAudienceValidator(expectedAudience: expectedAudience, required: required)
            case .exp(let required):
                return ExpirationTimeValidator(required: required)
            case .nbf(let required):
                return NotBeforeTimeValidator(required: required)
            case .iat(let required):
                return IssuedAtValidator(required: required)
            case .custom(let claimValidator):
                return claimValidator
            }
        }
    }
    
    /// Verifies a JWT string and returns a decoded JWT if successful.
    ///
    /// This method supports both JWS (JSON Web Signature) and JWE (JSON Web Encryption) formats. It first determines the format of the JWT based on the number of components separated by dots in the JWT string. The method also handles nested JWTs, verifying each layer as needed.
    ///
    /// This method supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be verified and decoded.
    ///   - senderKey: An optional `KeyRepresentable` representing the sender's key, used for verifying a JWS.
    ///   - recipientKey: An optional `KeyRepresentable` representing the recipient's key, used for decrypting a JWE.
    ///   - nestedKeys: An array of `KeyRepresentable` used for verifying nested JWTs.
    ///   - validators: An array of `ClaimValidator` used to validate the JWT claims, if not set as default the `ExpirationTimeValidator`, `NotBeforeTimeValidator` and `IssuedAtValidator` will be used.
    /// - Returns: A `JWT` instance containing the payload and format.
    /// - Throws: `JWTError` if verification fails, the signature is invalid, claims validation fails, the JWT format is incorrect, or if nested JWT keys are missing.
    public static func verify(
        jwtString: String,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        nestedKeys: [KeyRepresentable] = [],
        validators: [Validator] = [
            .exp(required: false),
            .nbf(required: false),
            .iat(required: false)
        ]
    ) throws -> JWT {
        let components = jwtString.components(separatedBy: ".")
        switch components.count {
        case 3:
            let jws = try JWS(jwsString: jwtString)
            if jws.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWSHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jws.protectedHeader
                ) else {
                    return try verifyNestedWithMultipleKeys(
                        jwtString: jws.payload.tryToString(),
                        senderKey: senderKey,
                        recipientKey: recipientKey,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                }
                
                return try verify(
                    jwtString: jws.payload.tryToString(),
                    senderKey: key,
                    recipientKey: nil,
                    nestedKeys: nestedKeys,
                    validators: validators
                )
            }
            
            guard try jws.verify(key: senderKey) else {
                throw JWTError.invalidSignature
            }
            try validateClaimsCluster(jwtString, validators: validators.map(\.validator))
            return .init(payload: jws.payload, format: .jws(jws))
        case 5:
            let jwe = try JWE(compactString: jwtString)
            
            let decryptedPayload = try jwe.decrypt(
                senderKey: senderKey,
                recipientKey: recipientKey
            )
            
            if jwe.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWEHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jwe.protectedHeader
                ) else {
                    return try verifyNestedWithMultipleKeys(
                        jwtString: decryptedPayload.tryToString(),
                        senderKey: senderKey,
                        recipientKey: recipientKey,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                }
                
                return try verify(
                    jwtString: decryptedPayload.tryToString(),
                    senderKey: senderKey,
                    recipientKey: key,
                    nestedKeys: nestedKeys,
                    validators: validators
                )
            }
            try validateClaimsCluster(jwtString, validators: validators.map(\.validator))
            
            return .init(payload: decryptedPayload, format: .jwe(jwe))
        default:
            throw JWTError.somethingWentWrong
        }
    }
    
    /// Verifies a JSON Web Token (JWT) string by checking its signature and claims.
    ///
    /// This method supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be verified.
    ///   - signerKey: The cryptographic key used for verifying the JWS, which can be of type `KeyRepresentable`.
    ///   - senderKey: The cryptographic key used for verifying the JWS, which can be of type `KeyRepresentable`.
    ///   - recipientKey: The cryptographic key used for verifying the JWS, which can be of type `KeyRepresentable`.
    ///   - nestedKeys: An array of `KeyRepresentable` used for verifying nested JWTs, if applicable.
    ///   - validators: An array of `ClaimValidator` used to validate the JWT claims, if not set as default the `ExpirationTimeValidator`, `NotBeforeTimeValidator` and `IssuedAtValidator` will be used.
    ///
    /// - Throws: An error if the verification process fails.
    /// - Returns: A `JWT` instance representing the verified JWT.
    public static func verify(
        jwtString: String,
        signerKey: KeyRepresentable? = nil,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        nestedKeys: [KeyRepresentable] = [],
        validators: [Validator] = [
            .exp(required: false),
            .nbf(required: false),
            .iat(required: false)
        ]
    ) throws -> JWT {
        let components = jwtString.components(separatedBy: ".")
        switch components.count {
        case 3:
            let jws = try JWS(jwsString: jwtString)
            if jws.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWSHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jws.protectedHeader
                ) else {
                    return try verifyNestedWithMultipleKeys(
                        jwtString: jws.payload.tryToString(),
                        senderKey: senderKey,
                        recipientKey: recipientKey,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                }
                
                return try verify(
                    jwtString: jws.payload.tryToString(),
                    senderKey: key,
                    recipientKey: nil,
                    nestedKeys: nestedKeys,
                    validators: validators
                )
            }
            
            guard try jws.verify(key: signerKey) else {
                throw JWTError.invalidSignature
            }
            try validateClaimsCluster(jwtString, validators: validators.map(\.validator))
            return .init(payload: jws.payload, format: .jws(jws))
        case 5:
            let jwe = try JWE(compactString: jwtString)
            
            let decryptedPayload = try jwe.decrypt(
                senderKey: senderKey,
                recipientKey: recipientKey
            )
            
            if jwe.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWEHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jwe.protectedHeader
                ) else {
                    return try verifyNestedWithMultipleKeys(
                        jwtString: decryptedPayload.tryToString(),
                        senderKey: senderKey,
                        recipientKey: recipientKey,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                }
                
                return try verify(
                    jwtString: decryptedPayload.tryToString(),
                    senderKey: senderKey,
                    recipientKey: key,
                    nestedKeys: nestedKeys,
                    validators: validators
                )
            }
            try validateClaimsCluster(jwtString, validators: validators.map(\.validator))
            
            return .init(payload: decryptedPayload, format: .jwe(jwe))
        default:
            throw JWTError.somethingWentWrong
        }
    }
    
    /// Validates the claims of this JWT instance using the provided validators.
    ///
    /// This method applies each validator from the given array to the JWT's claims. It delegates the actual
    /// validation to the static method, which maps each `Validator` enum case to its corresponding `ClaimValidator`
    /// implementation before performing the validations.
    ///
    /// - Parameter validators: An array of `Validator` used to validate specific claims within the JWT.
    /// - Throws: A `JWT.JWTError` if any of the validations fail, such as when a required claim is missing or invalid.
    public func validateClaims(validators: [Validator]) throws {
        try Self.validateClaims(self.jwtString, validators: validators)
    }

    /// Validates the claims of a JWT string using the provided validators.
    ///
    /// This static method takes a JWT string and an array of `Validator` instances. It maps each validator to its
    /// concrete `ClaimValidator` implementation and then passes them to an internal validation cluster function.
    /// If any validator fails, the method throws the corresponding `JWT.JWTError`.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string whose claims are to be validated.
    ///   - validators: An array of `Validator` used to validate specific claims within the JWT.
    /// - Throws: A `JWT.JWTError` if any of the claim validations fail.
    public static func validateClaims(_ jwtString: String, validators: [Validator]) throws {
        try validateClaimsCluster(jwtString, validators: validators.map(\.validator))
    }
    
    private static func verifyNestedWithMultipleKeys(
        jwtString: String,
        senderKey: KeyRepresentable?,
        recipientKey: KeyRepresentable?,
        nestedKeys: [KeyRepresentable],
        validators: [Validator]
    ) throws -> JWT {
        for key in nestedKeys {
            do {
                switch try jwtFormat(jwtString: jwtString) {
                case .jws:
                    return try verify(
                        jwtString: jwtString,
                        senderKey: key,
                        recipientKey: recipientKey,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                case .jwe:
                    return try verify(
                        jwtString: jwtString,
                        senderKey: senderKey,
                        recipientKey: key,
                        nestedKeys: nestedKeys,
                        validators: validators
                    )
                }
                
            } catch {
                continue
            }
        }
        throw JWTError.missingNestedJWTKey
    }
}

private func validateClaimsCluster(_ jwtString: String, validators: [ClaimValidator]) throws {
    var collectedErrors = [Error]()
    validators.forEach {
        do {
            try $0.isValid(jwtString)
        } catch {
            collectedErrors.append(error)
        }
    }
    
    if collectedErrors.isEmpty { return }
    if collectedErrors.count == 1, let error = collectedErrors.first {
        throw error
    } else {
        throw JWT.JWTError.multipleValidatingErrors(collectedErrors)
    }
}

private func getKeyForJWSHeader(keys: [JWK], header: JWSRegisteredFieldsHeader?) -> JWK? {
    keys.first {
        if let thumbprint = try? $0.thumbprint() {
            if thumbprint == header?.keyID {
                return true
            }
            
            if
                let hThumbprint = try? header?.jwk?.thumbprint(),
                hThumbprint == thumbprint
            {
                return true
            }
        }
        guard let header else { return false }
        
        if let x509Url = header.x509URL, x509Url == $0.x509URL { return true }
        if
            let x509CertificateSHA256Thumbprint = header.x509CertificateSHA256Thumbprint,
            x509CertificateSHA256Thumbprint == $0.x509CertificateSHA256Thumbprint
        { return true }
        
        if
            let x509CertificateSHA1Thumbprint = header.x509CertificateSHA1Thumbprint,
            x509CertificateSHA1Thumbprint == $0.x509CertificateSHA1Thumbprint
        { return true }
        
        if let keyID = header.keyID, keyID == $0.keyID { return true }
        
        return false
    }
}

private func getKeyForJWEHeader(keys: [JWK], header: JWERegisteredFieldsHeader?) -> JWK? {
    keys.first {
        if let thumbprint = try? $0.thumbprint() {
            if thumbprint == header?.keyID {
                return true
            }
            
            if
                let hThumbprint = try? header?.jwk?.thumbprint(),
                hThumbprint == thumbprint
            {
                return true
            }
        }
        guard let header else { return false }
        
        if let x509Url = header.x509URL, x509Url == $0.x509URL { return true }
        if
            let x509CertificateSHA256Thumbprint = header.x509CertificateSHA256Thumbprint,
            x509CertificateSHA256Thumbprint == $0.x509CertificateSHA256Thumbprint
        { return true }
        
        if
            let x509CertificateSHA1Thumbprint = header.x509CertificateSHA1Thumbprint,
            x509CertificateSHA1Thumbprint == $0.x509CertificateSHA1Thumbprint
        { return true }
        
        if let keyID = header.keyID, keyID == $0.keyID { return true }
        
        return false
    }
}
