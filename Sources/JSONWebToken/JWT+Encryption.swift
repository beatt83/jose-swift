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
import JSONWebEncryption

extension JWT {
    
    /// Encrypts the payload of a JWT and returns it in JWE format.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload to encrypt, conforming to `JWTRegisteredFieldsClaims`.
    ///   - protectedHeader: A header with fields that will be protected (encrypted).
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted).
    ///   - senderKey: An optional `JWK` representing the sender's key.
    ///   - recipientKey: An optional `JWK` representing the recipient's key.
    ///   - sharedKey: An optional shared symmetric key used in key agreement protocols.
    ///   - cek: An optional content encryption key.
    ///   - initializationVector: An optional initialization vector for the encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload.
    /// - Returns: An instance of `JWT` in JWE format with the encrypted payload.
    /// - Throws: An error if the encryption process fails.
    public static func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: Codable,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable?,
        recipientKey: KeyRepresentable?,
        sharedKey: KeyRepresentable?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        protectedHeader.type = "JWT"
        let encodedPayload = try JSONEncoder.jwt.encode(payload)
        return JWT(
            payload: encodedPayload,
            format: .jwe(try JWE(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                senderKey: senderKey,
                recipientKey: recipientKey,
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData
            ))
        )
    }
    
    public static func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        @JWTClaimsBuilder payload: () -> Claim,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable?,
        recipientKey: KeyRepresentable?,
        sharedKey: KeyRepresentable?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        protectedHeader.type = "JWT"
        let encodedPayload = try JSONEncoder.jwt.encode(payload().value)
        return JWT(
            payload: encodedPayload,
            format: .jwe(try JWE(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                senderKey: senderKey,
                recipientKey: recipientKey,
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData
            ))
        )
    }
    
    /// Encrypts a JWT string as a nested JWT in JWE format.
    ///
    /// This method is used for creating a nested JWT, where the payload is another JWT string.
    /// It encrypts the provided JWT string and wraps it in a new JWE structure.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be encrypted.
    ///   - protectedHeader: A header with fields that will be protected (encrypted) in the outer JWE layer.
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the outer JWE layer.
    ///   - senderKey: An optional `JWK` representing the sender's key for the outer JWE layer.
    ///   - recipientKey: An optional `JWK` representing the recipient's key for the outer JWE layer.
    ///   - sharedKey: An optional shared symmetric key used in key agreement protocols for the outer JWE layer.
    ///   - cek: An optional content encryption key for the outer JWE layer.
    ///   - initializationVector: An optional initialization vector for the outer JWE encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload for the outer JWE layer.
    /// - Returns: A string representing the encrypted JWT in JWE format.
    /// - Throws: An error if the encryption process fails.
    public static func encryptAsNested<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        jwt: JWT,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        sharedKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWE {
        var protectedHeader = protectedHeader
        protectedHeader.contentType = "JWT"
        
        return try JWE(
            payload: jwt.jwtString.tryToData(),
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    /// Encrypts a JWT payload as a nested JWT in JWE format with distinct outer and inner JWE headers.
    ///
    /// This method creates a nested JWE structure with two layers of encryption. The inner layer encrypts the payload,
    /// and the outer layer encrypts the resulting JWT from the inner encryption.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload to encrypt, conforming to `JWTRegisteredFieldsClaims`.
    ///   - protectedHeader: A header with fields that will be protected (encrypted) in the outer JWE layer.
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the outer JWE layer.
    ///   - senderKey: An optional `JWK` representing the sender's key for the outer JWE layer.
    ///   - recipientKey: An optional `JWK` representing the recipient's key for the outer JWE layer.
    ///   - sharedKey: An optional shared symmetric key used in key agreement protocols for the outer JWE layer.
    ///   - cek: An optional content encryption key for the outer JWE layer.
    ///   - initializationVector: An optional initialization vector for the outer JWE encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload for the outer JWE layer.
    ///   - nestedProtectedHeader: A header with fields that will be protected (encrypted) in the inner JWE layer.
    ///   - nestedUnprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the inner JWE layer.
    ///   - nestedSenderKey: An optional `JWK` representing the sender's key for the inner JWE layer.
    ///   - nestedRecipientKey: An optional `JWK` representing the recipient's key for the inner JWE layer.
    ///   - nestedSharedKey: An optional shared symmetric key used in key agreement protocols for the inner JWE layer.
    ///   - nestedCek: An optional content encryption key for the inner JWE layer.
    ///   - nestedInitializationVector: An optional initialization vector for the inner JWE encryption algorithm.
    ///   - nestedAdditionalAuthenticationData: Optional additional data authenticated along with the payload for the inner JWE layer.
    /// - Returns: A `JWE` instance representing the doubly encrypted nested JWT.
    /// - Throws: An error if the encryption process fails.
    public static func encryptAsNested<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        NP: JWERegisteredFieldsHeader,
        NU: JWERegisteredFieldsHeader
    >(
        payload: Codable,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        sharedKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        nestedProtectedHeader: NP,
        nestedUnprotectedHeader: NU? = nil as DefaultJWEHeaderImpl?,
        nestedSenderKey: KeyRepresentable? = nil,
        nestedRecipientKey: KeyRepresentable? = nil,
        nestedSharedKey: KeyRepresentable? = nil,
        nestedCek: Data? = nil,
        nestedInitializationVector: Data? = nil,
        nestedAdditionalAuthenticationData: Data? = nil
    ) throws -> JWE {
        let jwt = try encrypt(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            unprotectedHeader: nestedUnprotectedHeader,
            senderKey: nestedSenderKey,
            recipientKey: nestedRecipientKey,
            sharedKey: nestedSharedKey,
            cek: nestedCek,
            initializationVector: nestedInitializationVector,
            additionalAuthenticationData: nestedAdditionalAuthenticationData
        )
        
        return try encryptAsNested(
            jwt: jwt,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    public static func encryptAsNested<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        NP: JWERegisteredFieldsHeader,
        NU: JWERegisteredFieldsHeader
    >(
        @JWTClaimsBuilder payload: () -> Claim,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        sharedKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        nestedProtectedHeader: NP,
        nestedUnprotectedHeader: NU? = nil as DefaultJWEHeaderImpl?,
        nestedSenderKey: KeyRepresentable? = nil,
        nestedRecipientKey: KeyRepresentable? = nil,
        nestedSharedKey: KeyRepresentable? = nil,
        nestedCek: Data? = nil,
        nestedInitializationVector: Data? = nil,
        nestedAdditionalAuthenticationData: Data? = nil
    ) throws -> JWE {
        let jwt = try encrypt(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            unprotectedHeader: nestedUnprotectedHeader,
            senderKey: nestedSenderKey,
            recipientKey: nestedRecipientKey,
            sharedKey: nestedSharedKey,
            cek: nestedCek,
            initializationVector: nestedInitializationVector,
            additionalAuthenticationData: nestedAdditionalAuthenticationData
        )
        
        return try encryptAsNested(
            jwt: jwt,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
}
