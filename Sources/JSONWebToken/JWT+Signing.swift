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
import JSONWebSignature

extension JWT {
    /// Creates a signed JSON Web Token (JWT) using the provided payload, header, and key.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    /// When using `Data` as the key type, the `alg` (algorithm) field must be set in the header.
    ///
    /// - Parameters:
    ///   - payload: The payload to be included in the JWT, conforming to `Codable`.
    ///   - protectedHeader: The protected header fields conforming to `JWSRegisteredFieldsHeader`.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` and `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or encoding fails.
    /// - Returns: A `JWT` instance in JWS format with the signed payload.
    public static func signed<P: JWSRegisteredFieldsHeader, Key>(
        payload: Codable,
        protectedHeader: P,
        key: Key?
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        if protectedHeader.type == nil {
            protectedHeader.type = "JWT"
        }
        let encodedPayload = try JSONEncoder.jwt.encode(payload)
        return JWT(
            payload: encodedPayload,
            format: .jws(try JWS(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                key: key
            ))
        )
    }
    
    /// Creates a signed JSON Web Token (JWT) using the provided claims, protected header, and cryptographic key.
    ///
    /// This method supports various key types conforming to `KeyRepresentable`, including `Data`, `JWK`, `SecKey`, `CryptoSwift.RSA`,
    /// CryptoKit EC Keys, and Curve25519. When using `Data` as the key type, ensure that the header’s `alg` (algorithm) field is set.
    ///
    /// - Parameters:
    ///   - claims: A closure that returns the claims to be included in the JWT using the `JWTClaimsBuilder`.
    ///   - protectedHeader: The protected header fields conforming to `JWSRegisteredFieldsHeader`.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` or any type conforming to `KeyRepresentable`.
    /// - Throws: An error if the signing or encoding process fails.
    /// - Returns: A `JWT` instance in JWS format containing the signed claims.
    public static func signed<P: JWSRegisteredFieldsHeader, Key>(
        @JWTClaimsBuilder claims: () -> Claim,
        protectedHeader: P,
        key: Key?
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        if protectedHeader.type == nil {
            protectedHeader.type = "JWT"
        }
        let encodedPayload = try JSONEncoder.jwt.encode(claims().value)
        return JWT(
            payload: encodedPayload,
            format: .jws(try JWS(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                key: key
            ))
        )
    }
    
    /// Creates a nested JSON Web Signature (JWS) object by first signing the payload as a JWT and then nesting it inside another JWS.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload to be included in the inner JWT, conforming to `Codable`.
    ///   - protectedHeader: The protected header fields for the outer JWS, conforming to `JWSRegisteredFieldsHeader`.
    ///   - key: The cryptographic key used for signing, which can be of type `KeyRepresentable`.
    ///   - nestedProtectedHeader: The protected header fields for the inner JWT, conforming to `JWSRegisteredFieldsHeader`.
    ///   - nestedKey: The cryptographic key used for signing, which can be of type `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or encoding fails.
    /// - Returns: A `JWS` instance representing the nested signed JWT.
    public static func signedAsNested<
        P: JWSRegisteredFieldsHeader,
        NP: JWSRegisteredFieldsHeader
    >(
        payload: Codable,
        protectedHeader: P,
        key: KeyRepresentable?,
        nestedProtectedHeader: NP,
        nestedKey: KeyRepresentable?
    ) throws -> JWS {
        let jwt = try signed(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            key: nestedKey
        )
        
        return try signedAsNested(
            jwtString: jwt.jwtString,
            protectedHeader: protectedHeader,
            key: key
        )
    }
    
    /// Creates a nested JWS (JSON Web Signature) by signing claims into an inner JWT and then wrapping it in an outer JWS.
    ///
    /// This method first creates an inner JWT using the provided claims, nested protected header, and nested signing key.
    /// It then signs the resulting JWT string with the outer protected header and signing key, producing a nested JWS.
    ///
    /// This initializer supports various key types conforming to `KeyRepresentable`, including `Data`, `JWK`, `SecKey`, `CryptoSwift.RSA`,
    /// CryptoKit EC Keys, and Curve25519. When using `Data` as the key type, ensure that the header’s `alg` (algorithm) field is set.
    ///
    /// - Parameters:
    ///   - claims: A closure that returns the claims to be included in the inner JWT using the `JWTClaimsBuilder`.
    ///   - protectedHeader: The protected header for the outer JWS layer.
    ///   - key: The cryptographic key used for signing the outer JWS, which can be of type `Data` or any type conforming to `KeyRepresentable`.
    ///   - nestedProtectedHeader: The protected header for the inner (nested) JWT.
    ///   - nestedKey: The cryptographic key used for signing the inner JWT, which can be of type `Data` or any type conforming to `KeyRepresentable`.
    /// - Throws: An error if either the inner or outer signing process fails.
    /// - Returns: A `JWS` instance representing the nested signed JWT.
    public static func signedAsNested<
        P: JWSRegisteredFieldsHeader,
        NP: JWSRegisteredFieldsHeader
    >(
        @JWTClaimsBuilder claims: () -> Claim,
        protectedHeader: P,
        key: KeyRepresentable?,
        nestedProtectedHeader: NP,
        nestedKey: KeyRepresentable?
    ) throws -> JWS {
        let jwt = try signed(
            claims: claims,
            protectedHeader: nestedProtectedHeader,
            key: nestedKey
        )
        
        return try signedAsNested(
            jwtString: jwt.jwtString,
            protectedHeader: protectedHeader,
            key: key
        )
    }
    
    /// Creates a nested JSON Web Signature (JWS) object by wrapping an existing JWT string inside another JWS.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwtString: The existing JWT string to be nested inside the outer JWS.
    ///   - protectedHeader: The protected header fields for the outer JWS, conforming to `JWSRegisteredFieldsHeader`.
    ///   - key: The cryptographic key used for signing, which can be of type `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or encoding fails.
    /// - Returns: A `JWS` instance representing the nested signed JWT.
    public static func signedAsNested<P: JWSRegisteredFieldsHeader>(
        jwtString: String,
        protectedHeader: P,
        key: KeyRepresentable?
    ) throws -> JWS {
        var protectedHeader = protectedHeader
        if protectedHeader.contentType == nil {
            protectedHeader.contentType = "JWT"
        }
        
        return try JWS(
            payload: JSONEncoder.jwt.encode(jwtString.tryToData()),
            protectedHeader: protectedHeader,
            key: key
        )
    }
    
    /// Resigns a signed JSON Web Token (JWT) using a new key.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - key: The cryptographic key used for signing, which can be of type `Data` and `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or encoding fails.
    /// - Returns: A `JWT` instance in JWS format with the signed payload.
    public func resign(key: KeyRepresentable) throws -> JWT {
        guard case let .jws(jws) = self.format else {
            throw JWTError.unsupportedFormat
        }
        
        let newJWS = try JWS(payload: jws.payload, protectedHeaderData: jws.protectedHeaderData, key: key)
        return JWT(payload: newJWS.payload, format: .jws(newJWS))
    }
}
