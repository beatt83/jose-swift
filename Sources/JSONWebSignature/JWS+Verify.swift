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

extension JWS {
    /// Verifies the signature of the JWS using the provided key.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - key: The cryptographic key used for signing, which can be of type `Data` and `KeyRepresentable`.
    ///
    /// - Throws: An error if the verification process fails due to a missing key, unsupported algorithm, or other issues.
    /// - Returns: A Boolean value indicating whether the signature is valid (`true`) or not (`false`).
    public func verify<Key>(key: Key?) throws -> Bool {
        guard SigningAlgorithm.none != protectedHeader.algorithm else {
            return true
        }
        guard let key else { throw JWSError.missingKey }
        let jwkKey = try prepareJWK(header: protectedHeaderData, key: key)
        try jwkKey.algorithm.map {
            guard $0 == protectedHeader.algorithm?.rawValue else {
                throw JWSError.keyAlgorithmAndHeaderAlgorithmAreNotEqual(
                    header: protectedHeader.algorithm?.rawValue ?? "",
                    key: $0
                )
            }
        }
        
        guard
            let verifier = protectedHeader.algorithm?.cryptoVerifier
        else {
            throw JWSError.unsupportedAlgorithm(
                keyType: protectedHeader.jwk?.keyType.rawValue,
                algorithm: protectedHeader.algorithm?.rawValue,
                curve: protectedHeader.jwk?.curve?.rawValue
            )
        }
        let signingData = try JWS.buildSigningData(header: protectedHeaderData, data: payload)
        return try verifier.verify(data: signingData, signature: signature, key: jwkKey)
    }
    
    /// Verifies the signature of a JWS JSON object using a single JSON Web Key (JWK).
    /// Can validate either all signatures or just one, depending on the `validateAll` parameter.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwsJson: The JWS JSON data to be verified.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` and `KeyRepresentable`.
    ///   - validateAll: If `true`, validates all signatures; otherwise, validates at least one.
    /// - Returns: `true` if the signature(s) are valid according to the provided parameters, `false` otherwise.
    /// - Throws: `JWSError` for errors encountered during verification.
    public static func verify<Key>(jwsJson: Data, key: Key, validateAll: Bool = false) throws -> Bool {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try decodeFullOrFlattenedJson(json: jwsJson)
        let jwkKey = try prepareJWK(header: JSONEncoder.jose.encode(json), key: key)
        if validateAll {
            guard try json.signatures
                .map({ try $0.jws(payload: json.payload) })
                .contains(where: { (try? $0.verify(key: jwkKey)) ?? false })
            else {
                return false
            }
            return true
        } else {
            let filteredSignatures = json.findSignaturesForJWK(jwk: jwkKey)
            guard !filteredSignatures.isEmpty else {
                throw JWSError.noSignatureForJWK(jwkAlg: jwkKey.algorithm, jwkKid: jwkKey.keyID)
            }
            return try filteredSignatures.map { try $0.jws(payload: json.payload) }.allSatisfy { try $0.verify(key: jwkKey) }
        }
    }
    
    /// Verifies the signature of a JSON Web Signature (JWS) object using the provided key.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwsJson: The JSON-encoded JWS object as `Data`.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` and `KeyRepresentable`.
    ///
    /// - Throws: An error if the verification process fails due to an invalid JWS format, missing key, or other issues.
    /// - Returns: A Boolean value indicating whether at least one signature in the JWS is valid (`true`) or not (`false`).
    public static func verify<Key>(jwsJson: Data, key: Key) throws -> Bool {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try decodeFullOrFlattenedJson(json: jwsJson)
        guard try json.signatures
            .map({ try $0.jws(payload: json.payload) })
            .contains(where: { (try? $0.verify(key: key)) ?? false })
        else {
            return false
        }
        return true
    }
    
    /// Verifies the signature of a JWS JSON object using an array of JSON Web Keys (JWKs).
    /// Depending on the `allNeedToVerify` parameter, either all keys need to verify the signature successfully,
    /// or at least one key needs to succeed.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - jwsJson: The JWS JSON data to be verified.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    ///   - allNeedToVerify: If `true`, all keys must verify the signature successfully; otherwise, at least one key must succeed.
    /// - Returns: `true` if the signature(s) are valid according to the provided parameters, `false` otherwise.
    /// - Throws: `JWSError` for errors encountered during verification.
    public static func verify(jwsJson: Data, keys: [KeyRepresentable], allNeedToVerify: Bool = false) throws -> Bool {
        if allNeedToVerify {
            return try keys.allSatisfy { try JWS.verify(jwsJson: jwsJson, key: $0) }
        } else {
            return try keys.contains { try JWS.verify(jwsJson: jwsJson, key: $0) }
        }
    }
    
    /// Verifies the signature of a JSON Web Signature (JWS) object using an array of provided keys.
    ///
    /// This initializer supports different types for the `Key` parameter, including `Data`, and `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    /// When using `Data` as the key type, the `alg` (algorithm) field must be set in the header.
    ///
    /// - Parameters:
    ///   - jwsJson: The JSON-encoded JWS object as `Data`.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    ///   - allNeedToVerify: A Boolean value indicating whether all signatures need to be verified (`true`) or if at least one valid signature is sufficient (`false`). Default is `false`.
    ///
    /// - Throws: An error if the verification process fails due to an invalid JWS format, missing key, or other issues.
    /// - Returns: A Boolean value indicating whether the verification criteria are met. If `allNeedToVerify` is `true`, returns `true` if all signatures are valid. If `allNeedToVerify` is `false`, returns `true` if at least one signature is valid.
    public static func verify<Key>(jwsJson: Data, keys: [Key], allNeedToVerify: Bool = false) throws -> Bool {
        if allNeedToVerify {
            return try keys.allSatisfy { try JWS.verify(jwsJson: jwsJson, key: $0) }
        } else {
            return try keys.contains { try JWS.verify(jwsJson: jwsJson, key: $0) }
        }
    }
}

func decodeFullOrFlattenedJson<
    P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader
>(json: Data) throws -> JWSJson<P, H> {
    guard
        let completeJson = try? JSONDecoder()
            .decode(
                JWSJson<P, H>.self,
                from: json
    ) else {
        guard let flattened = try? JSONDecoder().decode(JWSJsonFlattened<P, H>.self, from: json) else {
            throw JWS.JWSError.couldNotDecodeCompleteJsonOrFlattened
        }
        return try flattened.fullJson()
    }
    return completeJson
}
