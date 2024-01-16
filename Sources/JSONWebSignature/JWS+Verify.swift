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
import JSONWebKey

extension JWS {
    /// Verifies the signature of the JWS instance using the provided JSON Web Key (JWK).
    ///
    /// - Parameter key: The `JWK` used for verification.
    /// - Returns: `true` if the signature is valid, `false` otherwise.
    /// - Throws: `JWSError` if there's a mismatch in algorithms between the key and the header,
    ///           if the algorithm is unsupported, or other errors encountered during verification.
    public func verify(key: JWK) throws -> Bool {
        try key.algorithm.map {
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
        let signingData = try JWS.buildSigningData(header: header, data: data)
        return try verifier.verify(data: signingData, signature: signature, key: key)
    }
    
    /// Verifies the signature of a JWS JSON object using a single JSON Web Key (JWK).
    /// Can validate either all signatures or just one, depending on the `validateAll` parameter.
    ///
    /// - Parameters:
    ///   - jwsJson: The JWS JSON data to be verified.
    ///   - jwk: The `JWK` used for verification.
    ///   - validateAll: If `true`, validates all signatures; otherwise, validates at least one.
    /// - Returns: `true` if the signature(s) are valid according to the provided parameters, `false` otherwise.
    /// - Throws: `JWSError` for errors encountered during verification.
    public static func verify(jwsJson: Data, jwk: JWK, validateAll: Bool = false) throws -> Bool {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try decodeFullOrFlattenedJson(json: jwsJson)
        
        if validateAll {
            guard try json.signatures
                .map({ try $0.jws(payload: json.payload) })
                .contains(where: { (try? $0.verify(key: jwk)) ?? false })
            else {
                return false
            }
            return true
        } else {
            let filteredSignatures = json.findSignaturesForJWK(jwk: jwk)
            guard !filteredSignatures.isEmpty else {
                throw JWSError.noSignatureForJWK(jwkAlg: jwk.algorithm, jwkKid: jwk.keyID)
            }
            return try filteredSignatures.map { try $0.jws(payload: json.payload) }.allSatisfy { try $0.verify(key: jwk) }
        }
    }
    
    /// Verifies the signature of a JWS JSON object using an array of JSON Web Keys (JWKs).
    /// Depending on the `allNeedToVerify` parameter, either all keys need to verify the signature successfully,
    /// or at least one key needs to succeed.
    ///
    /// - Parameters:
    ///   - jwsJson: The JWS JSON data to be verified.
    ///   - jwks: An array of `JWK`s used for verification.
    ///   - allNeedToVerify: If `true`, all keys must verify the signature successfully; otherwise, at least one key must succeed.
    /// - Returns: `true` if the signature(s) are valid according to the provided parameters, `false` otherwise.
    /// - Throws: `JWSError` for errors encountered during verification.
    public static func verify(jwsJson: Data, jwks: [JWK], allNeedToVerify: Bool = false) throws -> Bool {
        if allNeedToVerify {
            return try jwks.allSatisfy { try JWS.verify(jwsJson: jwsJson, jwk: $0) }
        } else {
            return try jwks.contains { try JWS.verify(jwsJson: jwsJson, jwk: $0) }
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
