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
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        if protectedHeader.type == nil {
            protectedHeader.type = "JWT"
        }
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
    
    /// Encrypts JWT claims into a JWE-formatted JWT using the provided headers, claims, and keys.
    ///
    /// This variant allows you to specify both a protected header and an optional unprotected header. The protected header
    /// fields will be cryptographically secured and included with the encrypted payload, while the unprotected header fields
    /// will remain in cleartext.
    ///
    /// The `@JWTClaimsBuilder` closure is used to construct the claims included in the JWT payload. The resulting claims are encoded
    /// and then encrypted based on the provided cryptographic parameters.
    ///
    /// - Parameters:
    ///   - claims: A closure marked with `@JWTClaimsBuilder` that constructs the JWT claims. The return value of this closure is wrapped in a `Claim` type.
    ///   - protectedHeader: A header conforming to `JWERegisteredFieldsHeader` that specifies the protected header fields.
    ///     If no `type` is provided in `protectedHeader`, it defaults to "JWT".
    ///   - unprotectedHeader: An optional header conforming to `JWERegisteredFieldsHeader` that specifies the unprotected header fields.
    ///   - senderKey: An optional `KeyRepresentable` representing the sender's key, used in key agreement protocols or authenticated encryption schemes.
    ///   - recipientKey: A `KeyRepresentable` representing the recipient's key. This key is necessary to decrypt and unwrap the Content Encryption Key (CEK).
    ///   - cek: An optional Content Encryption Key (`Data`). If not provided, one will be automatically generated.
    ///   - initializationVector: An optional initialization vector (`Data`) for the encryption algorithm. If not provided, one will be generated.
    ///   - additionalAuthenticationData: Optional additional data that will be authenticated but not encrypted. This helps ensure the integrity of any external data.
    ///
    /// - Returns: A `JWT` instance in JWE format containing the encrypted claims.
    ///
    /// - Throws:
    ///   - An encoding error if the claims cannot be encoded.
    ///   - A cryptographic error if encryption fails.
    ///   - Any other errors encountered during the encryption and wrapping process.
    public static func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        @JWTClaimsBuilder claims: () -> Claim,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable?,
        recipientKey: KeyRepresentable?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        if protectedHeader.type == nil {
            protectedHeader.type = "JWT"
        }
        let encodedPayload = try JSONEncoder.jwt.encode(claims().value)
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
    
    /// Encrypts a raw payload into a JWE-formatted JWT using the specified cryptographic algorithms and keys.
    ///
    /// This initializer allows you to provide a raw `Data` payload, along with explicit key management and content encryption algorithms.
    /// You can optionally specify a compression algorithm, as well as parameters for password-based encryption.
    ///
    /// The `senderKey` and `recipientKey` represent the keys involved in key wrapping or agreement. If `senderKey` is provided, it may be used for
    /// authenticated encryption or key agreement protocols. The `recipientKey` is generally required and represents the key that the recipient can
    /// use to decrypt the JWE. If `cek` (Content Encryption Key) is not provided, it will be generated automatically.
    ///
    /// The `initializationVector` (IV) is optional; if not provided, it will be generated automatically for supported encryption algorithms.
    /// The `additionalAuthenticationData` (AAD) can also be provided to add extra data that will be authenticated, but not encrypted, ensuring the integrity
    /// of this data during decryption.
    ///
    /// If `password` is provided along with `saltLength` and `iterationCount`, a password-based key derivation function will be used to derive the key.
    ///
    /// - Parameters:
    ///   - payload: The raw `Data` payload to encrypt.
    ///   - keyManagementAlg: The `KeyManagementAlgorithm` used to wrap or derive the key that protects the CEK.
    ///   - encryptionAlgorithm: The `ContentEncryptionAlgorithm` used to perform the actual encryption of the payload.
    ///   - compressionAlgorithm: An optional `ContentCompressionAlgorithm` for compressing the payload before encryption.
    ///   - senderKey: An optional `KeyRepresentable` for the sender's key, if key agreement or authenticated encryption is used.
    ///   - recipientKey: A `KeyRepresentable` for the recipient's key, required to unwrap or derive the CEK.
    ///   - cek: An optional CEK (`Data`). If not provided, one will be generated.
    ///   - initializationVector: An optional IV (`Data`). If not provided, one will be generated.
    ///   - additionalAuthenticationData: Additional data to authenticate, but not encrypt.
    ///   - password: An optional password (`Data`) for password-based encryption schemes.
    ///   - saltLength: An optional salt length for PBKDF, if password-based encryption is used.
    ///   - iterationCount: An optional iteration count for PBKDF, if password-based encryption is used.
    /// - Returns: A `JWT` in JWE format containing the encrypted payload.
    /// - Throws: An error if encryption fails, or if provided parameters are invalid.
    public static func encrypt(
        payload: Data,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWT {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            type: "JWT"
        )
        
        return JWT(
            payload: payload,
            format: .jwe(try JWE(
                payload: payload,
                protectedHeader: protectedHeader,
                senderKey: senderKey,
                recipientKey: recipientKey,
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData
            ))
        )
    }
    
    /// Encrypts JWT claims into a JWE-formatted JWT using the specified cryptographic algorithms and keys.
    ///
    /// This initializer takes claims built via a `@JWTClaimsBuilder` closure, allowing you to programmatically construct
    /// the claims to be included in the JWT payload. It supports the same parameters for key management and content
    /// encryption algorithms as its `Data`-payload counterpart, and it can also optionally compress and include
    /// password-based encryption parameters.
    ///
    /// The `senderKey` and `recipientKey` parameters define the keys used for encrypting the CEK (or deriving it), while
    /// `cek`, if not provided, will be automatically generated. The `initializationVector` is also optional, as is
    /// `additionalAuthenticationData`.
    ///
    /// If a `password` is provided along with `saltLength` and `iterationCount`, the encryption keys will be derived from
    /// the given password. This enables password-based encryption schemes.
    ///
    /// - Parameters:
    ///   - claims: A builder closure that returns a `Claim`. The `Claim` defines the JWT's payload.
    ///   - keyManagementAlg: The `KeyManagementAlgorithm` used for managing keys that protect the CEK.
    ///   - encryptionAlgorithm: The `ContentEncryptionAlgorithm` used for encrypting the JWT payload.
    ///   - compressionAlgorithm: An optional `ContentCompressionAlgorithm` for compressing the payload before encryption.
    ///   - senderKey: An optional `KeyRepresentable` for the sender's key, if key agreement or authenticated encryption is used.
    ///   - recipientKey: A `KeyRepresentable` for the recipient's key, required to unwrap or derive the CEK.
    ///   - cek: An optional CEK (`Data`). If not provided, one will be generated.
    ///   - initializationVector: An optional IV (`Data`). If not provided, one will be generated.
    ///   - additionalAuthenticationData: Additional data to be authenticated during decryption.
    ///   - password: An optional password (`Data`) for password-based encryption schemes.
    ///   - saltLength: An optional salt length for PBKDF, if password-based encryption is used.
    ///   - iterationCount: An optional iteration count for PBKDF, if password-based encryption is used.
    /// - Returns: A `JWT` in JWE format containing the encrypted claims.
    /// - Throws: An error if encryption fails, if the claims cannot be encoded, or if provided parameters are invalid.
    public static func encrypt(
        @JWTClaimsBuilder claims: () -> Claim,
        keyManagementAlg: KeyManagementAlgorithm,
        encryptionAlgorithm: ContentEncryptionAlgorithm,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        password: Data? = nil,
        saltLength: Int? = nil,
        iterationCount: Int? = nil
    ) throws -> JWT {
        let protectedHeader = DefaultJWEHeaderImpl(
            keyManagementAlgorithm: keyManagementAlg,
            encodingAlgorithm: encryptionAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            type: "JWT"
        )
        let encodedPayload = try JSONEncoder.jwt.encode(claims().value)
        
        return JWT(
            payload: encodedPayload,
            format: .jwe(try JWE(
                payload: encodedPayload,
                protectedHeader: protectedHeader,
                senderKey: senderKey,
                recipientKey: recipientKey,
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData
            ))
        )
    }
    
    /// Encrypts an inner JWT into a nested JWT represented in JWE format.
    ///
    /// This method creates a nested JWT by encrypting the inner JWT string and wrapping it within a new JWE structure.
    /// It supports various key types conforming to `KeyRepresentable`, including `JWK`, `SecKey`, `CryptoSwift.RSA`,
    /// CryptoKit EC Keys, and Curve25519.
    ///
    /// - Parameters:
    ///   - jwt: The inner JWT to be encrypted.
    ///   - protectedHeader: A header with fields that will be protected (encrypted) in the outer JWE layer. If the `contentType` is not set, it will default to `"JWT"`.
    ///   - unprotectedHeader: An optional header with fields that will remain unprotected (not encrypted) in the outer JWE layer.
    ///   - senderKey: An optional key representing the sender's key for the outer JWE encryption layer.
    ///   - recipientKey: An optional key representing the recipient's key for the outer JWE encryption layer.
    ///   - cek: An optional content encryption key for the outer JWE layer.
    ///   - initializationVector: An optional initialization vector for the outer JWE encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data to be authenticated along with the payload in the outer JWE layer.
    /// - Returns: A `JWT` instance representing the nested encrypted JWT in JWE format.
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
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        var protectedHeader = protectedHeader
        if protectedHeader.contentType == nil {
            protectedHeader.contentType = "JWT"
        }
        return JWT(
            payload: try jwt.jwtString.tryToData(),
            format: .jwe(try JWE(
                payload: jwt.jwtString.tryToData(),
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
    ///   - cek: An optional content encryption key for the outer JWE layer.
    ///   - initializationVector: An optional initialization vector for the outer JWE encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload for the outer JWE layer.
    ///   - nestedProtectedHeader: A header with fields that will be protected (encrypted) in the inner JWE layer.
    ///   - nestedUnprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the inner JWE layer.
    ///   - nestedSenderKey: An optional `JWK` representing the sender's key for the inner JWE layer.
    ///   - nestedRecipientKey: An optional `JWK` representing the recipient's key for the inner JWE layer.
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
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        nestedProtectedHeader: NP,
        nestedUnprotectedHeader: NU? = nil as DefaultJWEHeaderImpl?,
        nestedSenderKey: KeyRepresentable? = nil,
        nestedRecipientKey: KeyRepresentable? = nil,
        nestedCek: Data? = nil,
        nestedInitializationVector: Data? = nil,
        nestedAdditionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        let jwt = try encrypt(
            payload: payload,
            protectedHeader: nestedProtectedHeader,
            unprotectedHeader: nestedUnprotectedHeader,
            senderKey: nestedSenderKey,
            recipientKey: nestedRecipientKey,
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
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
    
    /// Encrypts a JWT payload as a nested JWT in JWE format with distinct outer and inner JWE headers,
    /// using a claims builder closure to construct the payload.
    ///
    /// This method creates a nested JWE structure by performing two layers of encryption:
    /// 1. The inner layer encrypts the JWT claims (constructed via the provided `claims` builder)
    ///    using the nested encryption parameters (headers, keys, and optional encryption values).
    /// 2. The outer layer then encrypts the resulting inner JWT using its own set of headers,
    ///    keys, and optional encryption parameters.
    ///
    /// This initializer supports different types for the `KeyRepresentable`. By default, types such as
    /// `JWK`, `SecKey`, `CryptoSwift.RSA`, and CriptoKit EC Keys (including Curve25519) extend `KeyRepresentable`
    /// and can be used as encryption keys.
    ///
    /// - Parameters:
    ///   - claims: A closure marked with `@JWTClaimsBuilder` that constructs and returns the JWT claims to encrypt.
    ///   - protectedHeader: A header with fields that will be protected (encrypted) in the outer JWE layer.
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the outer JWE layer.
    ///   - senderKey: An optional `KeyRepresentable` representing the sender's key for the outer JWE layer.
    ///   - recipientKey: An optional `KeyRepresentable` representing the recipient's key for the outer JWE layer.
    ///   - cek: An optional content encryption key for the outer JWE layer.
    ///   - initializationVector: An optional initialization vector for the outer JWE encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload for the outer JWE layer.
    ///   - nestedProtectedHeader: A header with fields that will be protected (encrypted) in the inner JWE layer.
    ///   - nestedUnprotectedHeader: An optional header with fields that will be unprotected (not encrypted) in the inner JWE layer.
    ///   - nestedSenderKey: An optional `KeyRepresentable` representing the sender's key for the inner JWE layer.
    ///   - nestedRecipientKey: An optional `KeyRepresentable` representing the recipient's key for the inner JWE layer.
    ///   - nestedCek: An optional content encryption key for the inner JWE layer.
    ///   - nestedInitializationVector: An optional initialization vector for the inner JWE encryption algorithm.
    ///   - nestedAdditionalAuthenticationData: Optional additional data authenticated along with the payload for the inner JWE layer.
    /// - Returns: A `JWT` instance representing the doubly encrypted nested JWT.
    /// - Throws: An error if either the inner or outer encryption process fails.
    public static func encryptAsNested<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        NP: JWERegisteredFieldsHeader,
        NU: JWERegisteredFieldsHeader
    >(
        @JWTClaimsBuilder claims: () -> Claim,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: KeyRepresentable? = nil,
        recipientKey: KeyRepresentable? = nil,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        nestedProtectedHeader: NP,
        nestedUnprotectedHeader: NU? = nil as DefaultJWEHeaderImpl?,
        nestedSenderKey: KeyRepresentable? = nil,
        nestedRecipientKey: KeyRepresentable? = nil,
        nestedCek: Data? = nil,
        nestedInitializationVector: Data? = nil,
        nestedAdditionalAuthenticationData: Data? = nil
    ) throws -> JWT {
        let jwt = try encrypt(
            claims: claims,
            protectedHeader: nestedProtectedHeader,
            unprotectedHeader: nestedUnprotectedHeader,
            senderKey: nestedSenderKey,
            recipientKey: nestedRecipientKey,
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
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        )
    }
}
