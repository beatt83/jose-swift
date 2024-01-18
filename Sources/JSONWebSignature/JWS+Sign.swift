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
import Tools

extension JWS {
    
    /// Initializes a new `JWS` instance using raw header data, payload data, and a JSON Web Key (JWK).
    /// The header is prepared for the JWK, and the signature is generated using the provided key.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeaderData: The raw header data.
    ///   - key: The `JWK` used for signing.
    /// - Throws: An error if the signing process fails, or if the key is missing.
    public init(payload: Data, protectedHeaderData: Data, key: JWK?) throws {
        let signature: Data
        let header = try prepareHeaderForJWK(header: protectedHeaderData, jwk: key)
        let protectedHeader = try JSONDecoder().decode(DefaultJWSHeaderImpl.self, from: header)
        if  let signer = protectedHeader.algorithm?.cryptoSigner {
            guard let key else {
                throw JWSError.missingKey
            }
            let signingData = try JWS.buildSigningData(header: header, data: payload)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.protectedHeaderData = header
        self.protectedHeader = protectedHeader
        self.payload = payload
        self.signature = signature
        self.compactSerialization = try JWS.buildJWSString(header: header, data: payload, signature: signature)
    }
    
    /// Initializes a new `JWS` instance using a `JWSProtectedFieldsHeader` instance, payload data, and a JSON Web Key (JWK).
    /// The header is encoded and then prepared for the JWK, and the signature is generated using the provided key.
    ///
    /// - Parameters:
    ///   - header: The `JWSProtectedFieldsHeader` instance.
    ///   - data: The payload data.
    ///   - key: The `JWK` used for signing.
    /// - Throws: An error if the signing process fails, or if the key is missing.
    public init(payload: Data, protectedHeader: JWSRegisteredFieldsHeader, key: JWK?) throws {
        let signature: Data
        let headerData = try JSONEncoder.jose.encode(protectedHeader)
        let header = try prepareHeaderForJWK(header: headerData, jwk: key)
        if let signer = protectedHeader.algorithm?.cryptoSigner {
            guard let key else {
                throw JWSError.missingKey
            }
            let signingData = try JWS.buildSigningData(header: headerData, data: payload)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.protectedHeaderData = header
        self.protectedHeader = protectedHeader
        self.payload = payload
        self.signature = signature
        self.compactSerialization = try JWS.buildJWSString(header: headerData, data: payload, signature: signature)
    }
    
    /// Convenience initializer to create a `JWS` instance using payload data and a JSON Web Key (JWK).
    /// The signing algorithm is determined from the key, and a default header is created and used.
    ///
    /// - Parameters:
    ///   - data: The payload data.
    ///   - key: The `JWK` used for signing.
    /// - Throws: An error if the signing process fails or if the key is inappropriate for the determined algorithm.
    public init(payload: Data, key: JWK) throws {
        let algorithm = try key.signingAlgorithm()
        let header = DefaultJWSHeaderImpl(algorithm: algorithm)
        try self.init(payload: payload, protectedHeader: header, key: key)
    }
    
    /// Generates a JSON serialization of the JWS object with multiple signatures, each corresponding to a different key in the provided array.
    /// This method is used when a payload needs to be signed with multiple keys.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: A `JWSJson` object representing the signed payload with multiple signatures.
    /// - Throws: An error if the signing process fails.
    static func jsonSerialization(
        payload: Data,
        keys: [JWK]
    ) throws -> JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> {
        let signatures = try keys
            .map {
                let jws = try JWS.init(payload: payload, key: $0)
                let header = $0.keyID != nil ? DefaultJWSHeaderImpl(from: $0) : jws.protectedHeader
                
                // This should never be triggered, I just feel the JWS interface is quite right, and dont want to add any generics.
                guard
                    let typedProtected = jws.protectedHeader as? DefaultJWSHeaderImpl,
                    let typedHeader = header as? DefaultJWSHeaderImpl
                else {
                    throw JWSError.somethingWentWrong
                }
                
                return try JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.Signature(
                    protectedData: jws.protectedHeaderData,
                    protected: typedProtected,
                    header: typedHeader,
                    signature: jws.signature
                )
            }
        
        return try jsonSerialization(payload: payload, signatures: signatures)
    }
    
    /// Encodes the JWS object with multiple signatures into JSON data.
    /// This is a wrapper around the `jsonSerialization(payload:keys:)` method that encodes the result into JSON.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: JSON encoded data representing the signed payload with multiple signatures.
    /// - Throws: An error if the JSON encoding process fails.
    public static func jsonSerialization(
        payload: Data,
        keys: [JWK]
    ) throws -> Data {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try jsonSerialization(payload: payload, keys: keys)
        return try JSONEncoder.jose.encode(json)
    }
    
    /// Generates a JSON serialization of the JWS object with signatures for a given payload, protected header, header, and keys.
    /// This method allows for specifying custom types for the protected header and header.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeader: The protected header instance.
    ///   - unprotectedHeader: An optional header instance.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: A `JWSJson` object with the specified header types.
    /// - Throws: An error if the signing process fails.
    static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        keys: [JWK]
    ) throws -> JWSJson<P, H> {
        let signatures = try keys
            .map {
                let jws = try JWS.init(payload: payload, protectedHeader: protectedHeader, key: $0)
                // This should never be triggered, I just feel the JWS interface is quite right, and dont want to add any generics.
                guard
                    let typedProtected = jws.protectedHeader as? P
                else {
                    throw JWSError.somethingWentWrong
                }
                
                return try JWSJson<P, H>.Signature(
                    protectedData: jws.protectedHeaderData,
                    protected: typedProtected,
                    header: unprotectedHeader,
                    signature: jws.signature
                )
            }
        
        return try jsonSerialization(payload: payload, signatures: signatures)
    }
    
    /// Encodes the JWS object into JSON data, allowing for custom protected header and header types.
    /// This method provides a way to serialize the JWS object with specified header types into JSON.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeader: The protected header instance.
    ///   - unprotectedHeader: An optional header instance.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: JSON encoded data with the specified header types.
    /// - Throws: An error if the JSON encoding process fails.
    public static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        keys: [JWK]
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            keys: keys
        )
        return try JSONEncoder.jose.encode(json)
    }
    
    static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        signatures: [JWSJson<P, H>.Signature]
    ) throws -> JWSJson<P, H> {
        return JWSJson<P, H>.init(payload: payload, signatures: signatures)
    }
    
    static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        signatures: [JWSJson<P, H>.Signature]
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(payload: payload, signatures: signatures)
        return try JSONEncoder.jose.encode(json)
    }
    
    /// Generates a flattened JSON serialization of the JWS object for a single key.
    /// This method is useful when there is only one signer and a compact JSON representation is preferred.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - key: The `JWK` used for signing.
    /// - Returns: Flattened JSON encoded data representing the signed payload.
    /// - Throws: An error if the signing or JSON encoding process fails.
    public static func jsonSerializationFlattened(
        payload: Data,
        key: JWK
    ) throws -> Data {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try jsonSerialization(payload: payload, keys: [key])
        return try JSONEncoder.jose.encode(json.flattened())
    }
    
    /// Generates a flattened JSON serialization of the JWS object for a single key, allowing for custom protected header and header types.
    /// This method is similar to `jsonSerializationFlattened(payload:key:)` but allows specifying custom header types.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeader: The protected header instance.
    ///   - unprotectedHeader: An optional header instance.
    ///   - key: The `JWK` used for signing.
    /// - Returns: Flattened JSON encoded data with the specified header types.
    /// - Throws: An error if the signing or JSON encoding process fails.
    public static func jsonSerializationFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        key: JWK
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            keys: [key]
        )
        
        return try JSONEncoder.jose.encode(json.flattened())
    }
    
    /// Generates a flattened JSON serialization of the JWS object for a single key, allowing for custom protected header and header types.
    /// This method is similar to `jsonSerializationFlattened(payload:key:)` but allows specifying custom header types.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeader: The protected header instance.
    ///   - unprotectedHeader: An optional header instance.
    ///   - key: The `JWK` used for signing.
    /// - Returns: A `JWSJsonFlattened` object with the specified header types.
    /// - Throws: An error if the signing or JSON encoding process fails.
    public static func jsonSerializationFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        key: JWK
    ) throws -> JWSJsonFlattened<P, H> {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            keys: [key]
        )
        
        return try json.flattened()
    }
}

private func prepareHeaderForJWK(header: Data, jwk: JWK?) throws -> Data {
    if
        var jsonObj = try JSONSerialization.jsonObject(with: header) as? [String: Any],
        jsonObj["alg"] == nil
    {
        jsonObj["alg"] = jwk?.algorithm as? String
        return try JSONSerialization.joseSerialization(withJSONObject: jsonObj)
    } else {
        return header
    }
}
