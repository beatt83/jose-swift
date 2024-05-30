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
    ///   - expectedIssuer: An optional expected issuer (`iss` claim) to validate.
    ///   - expectedAudience: An optional expected audience (`aud` claim) to validate.
    /// - Returns: A `JWT` instance containing the payload and format.
    /// - Throws: `JWTError` if verification fails, the signature is invalid, claims validation fails, the JWT format is incorrect, or if nested JWT keys are missing.
    public static func verify(
        jwtString: String,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        nestedKeys: [KeyRepresentable] = [],
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil
    ) throws -> JWT {
        let components = jwtString.components(separatedBy: ".")
        switch components.count {
        case 3:
            let jws = try JWS(jwsString: jwtString)
            if jws.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWSHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jws.protectedHeader
                ) else { throw JWTError.missingNestedJWTKey }
                
                return try verify(
                    jwtString: jws.payload.tryToString(),
                    senderKey: key,
                    recipientKey: nil,
                    nestedKeys: nestedKeys,
                    expectedIssuer: expectedIssuer,
                    expectedAudience: expectedAudience
                )
            }
            let payload = try JSONDecoder.jwt.decode(DefaultJWTClaimsImpl.self, from: jws.payload)
            
            guard try jws.verify(key: senderKey) else {
                throw JWTError.invalidSignature
            }
            try validateClaims(
                claims: payload,
                expectedIssuer: expectedIssuer,
                expectedAudience: expectedAudience
            )
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
                ) else { throw JWTError.missingNestedJWTKey }
                
                return try verify(
                    jwtString: decryptedPayload.tryToString(),
                    senderKey: senderKey,
                    recipientKey: key,
                    nestedKeys: nestedKeys,
                    expectedIssuer: expectedIssuer,
                    expectedAudience: expectedAudience
                )
            }
            let payload = try JSONDecoder.jwt.decode(DefaultJWTClaimsImpl.self, from: decryptedPayload)
            try validateClaims(
                claims: payload,
                expectedIssuer: expectedIssuer,
                expectedAudience: expectedAudience
            )
            
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
    ///   - expectedIssuer: The expected issuer (`iss`) claim in the JWT payload.
    ///   - expectedAudience: The expected audience (`aud`) claim in the JWT payload.
    ///
    /// - Throws: An error if the verification process fails.
    /// - Returns: A `JWT` instance representing the verified JWT.
    public static func verify(
        jwtString: String,
        signerKey: KeyRepresentable? = nil,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        nestedKeys: [KeyRepresentable] = [],
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil
    ) throws -> JWT {
        let components = jwtString.components(separatedBy: ".")
        switch components.count {
        case 3:
            let jws = try JWS(jwsString: jwtString)
            if jws.protectedHeader.contentType == "JWT" {
                guard let key = getKeyForJWSHeader(
                    keys: try nestedKeys.map { try $0.jwk },
                    header: jws.protectedHeader
                ) else { throw JWTError.missingNestedJWTKey }
                
                return try verify(
                    jwtString: jws.payload.tryToString(),
                    senderKey: key,
                    recipientKey: nil,
                    nestedKeys: nestedKeys,
                    expectedIssuer: expectedIssuer,
                    expectedAudience: expectedAudience
                )
            }
            let payload = try JSONDecoder.jwt.decode(DefaultJWTClaimsImpl.self, from: jws.payload)
            
            guard try jws.verify(key: signerKey) else {
                throw JWTError.invalidSignature
            }
            try validateClaims(
                claims: payload,
                expectedIssuer: expectedIssuer,
                expectedAudience: expectedAudience
            )
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
                ) else { throw JWTError.missingNestedJWTKey }
                
                return try verify(
                    jwtString: decryptedPayload.tryToString(),
                    senderKey: senderKey,
                    recipientKey: key,
                    nestedKeys: nestedKeys,
                    expectedIssuer: expectedIssuer,
                    expectedAudience: expectedAudience
                )
            }
            let payload = try JSONDecoder.jwt.decode(DefaultJWTClaimsImpl.self, from: decryptedPayload)
            try validateClaims(
                claims: payload,
                expectedIssuer: expectedIssuer,
                expectedAudience: expectedAudience
            )
            
            return .init(payload: decryptedPayload, format: .jwe(jwe))
        default:
            throw JWTError.somethingWentWrong
        }
    }
}

public func validateClaims(
    claims: JWTRegisteredFieldsClaims,
    expectedIssuer: String? = nil,
    expectedAudience: String? = nil
) throws {
    let currentDate = Date()

    // Validate Issuer
    if let expectedIssuer = expectedIssuer, let issuer = claims.iss {
        guard issuer == expectedIssuer else {
            throw JWT.JWTError.issuerMismatch
        }
    }

    // Validate Expiration Time
    if let expirationTime = claims.exp {
        guard currentDate < expirationTime else {
            throw JWT.JWTError.expired
        }
    }

    // Validate Not Before Time
    if let notBeforeTime = claims.nbf {
        guard currentDate >= notBeforeTime else {
            throw JWT.JWTError.notYetValid
        }
    }

    // Validate Issued At
    if let issuedAt = claims.iat {
        guard issuedAt <= currentDate else {
            throw JWT.JWTError.issuedInTheFuture
        }
    }

    // Validate Audience
    if let expectedAudience = expectedAudience, let audience = claims.aud {
        guard audience.contains(expectedAudience) else {
            throw JWT.JWTError.audienceMismatch
        }
    }
    
    try claims.validateExtraClaims()
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
