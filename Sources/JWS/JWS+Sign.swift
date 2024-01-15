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
import JWA
import JWK
import Tools

extension JWS {
    
    /// Initializes a new `JWS` instance using raw header data, payload data, and a JSON Web Key (JWK).
    /// The header is prepared for the JWK, and the signature is generated using the provided key.
    ///
    /// - Parameters:
    ///   - header: The raw header data.
    ///   - data: The payload data.
    ///   - key: The `JWK` used for signing.
    public init(header: Data, data: Data, key: JWK) throws {
        let signature: Data
        let header = try prepareHeaderForJWK(header: header, jwk: key)
        let protectedHeader = try JSONDecoder().decode(DefaultJWSHeaderImpl.self, from: header)
        if let signer = protectedHeader.algorithm?.cryptoSigner {
            let signingData = try JWS.buildSigningData(header: header, data: data)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.header = header
        self.protectedHeader = protectedHeader
        self.data = data
        self.signature = signature
        self.compactSerilization = try JWS.buildJWSString(header: header, data: data, signature: signature)
    }
    
    /// Initializes a new `JWS` instance using a `JWSProtectedFieldsHeader` instance, payload data, and a JSON Web Key (JWK).
    /// The header is encoded and then prepared for the JWK, and the signature is generated using the provided key.
    ///
    /// - Parameters:
    ///   - header: The `JWSProtectedFieldsHeader` instance.
    ///   - data: The payload data.
    ///   - key: The `JWK` used for signing.
    public init(header: JWSRegisteredFieldsHeader, data: Data, key: JWK) throws {
        let signature: Data
        let headerData = try JSONEncoder().encode(header)
        let header = try prepareHeaderForJWK(header: headerData, jwk: key)
        let protectedHeader = try JSONDecoder().decode(DefaultJWSHeaderImpl.self, from: header)
        if let signer = protectedHeader.algorithm?.cryptoSigner {
            let signingData = try JWS.buildSigningData(header: headerData, data: data)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.header = header
        self.protectedHeader = protectedHeader
        self.data = data
        self.signature = signature
        self.compactSerilization = try JWS.buildJWSString(header: headerData, data: data, signature: signature)
    }
    
    /// Convenience initializer to create a `JWS` instance using payload data and a JSON Web Key (JWK).
    /// The signing algorithm is determined from the key, and a default header is created and used.
    ///
    /// - Parameters:
    ///   - data: The payload data.
    ///   - key: The `JWK` used for signing.
    public init(data: Data, key: JWK) throws {
        let algorithm = try key.signingAlgorithm()
        let header = DefaultJWSHeaderImpl(algorithm: algorithm)
        let headerData = try JSONEncoder.jose.encode(header)
        try self.init(header: headerData, data: data, key: key)
    }
    
    /// Generates a JSON serialization of the JWS object with multiple signatures, each corresponding to a different key in the provided array.
    /// This method is used when a payload needs to be signed with multiple keys.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: A `JWSJson` object representing the signed payload with multiple signatures.
    static func jsonSerialization(
        payload: Data,
        keys: [JWK]
    ) throws -> JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> {
        let signatures = try keys
            .map {
                let jws = try JWS.init(data: payload, key: $0)
                let header = $0.keyID != nil ? DefaultJWSHeaderImpl(
                    algorithm: nil,
                    keyID: $0.keyID
                ) : jws.protectedHeader
                
                // This should never be triggered, I just feel the JWS interface is quite right, and dont want to add any generics.
                guard
                    let typedProtected = jws.protectedHeader as? DefaultJWSHeaderImpl,
                    let typedHeader = header as? DefaultJWSHeaderImpl
                else {
                    throw JWSError.somethingWentWrong
                }
                
                return try JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl>.Signature(
                    protectedData: jws.header,
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
    ///   - header: The header instance.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: A `JWSJson` object with the specified header types.
    static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        header: H,
        keys: [JWK]
    ) throws -> JWSJson<P, H> {
        let signatures = try keys
            .map {
                let jws = try JWS.init(header: protectedHeader, data: payload, key: $0)
                // This should never be triggered, I just feel the JWS interface is quite right, and dont want to add any generics.
                guard
                    let typedProtected = jws.protectedHeader as? P
                else {
                    throw JWSError.somethingWentWrong
                }
                
                return try JWSJson<P, H>.Signature(
                    protectedData: jws.header,
                    protected: typedProtected,
                    header: header,
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
    ///   - header: The header instance.
    ///   - keys: An array of `JWK`s used for signing.
    /// - Returns: JSON encoded data with the specified header types.
    public static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        header: H,
        keys: [JWK]
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            header: header,
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
    ///   - header: The header instance.
    ///   - key: The `JWK` used for signing.
    /// - Returns: Flattened JSON encoded data with the specified header types.
    public static func jsonSerializationFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        header: H,
        key: JWK
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            header: header,
            keys: [key]
        )
        
        return try JSONEncoder.jose.encode(json.flattened())
    }
}

private func prepareHeaderForJWK(header: Data, jwk: JWK) throws -> Data {
    guard
        var jsonObj = try JSONSerialization.jsonObject(with: header) as? [String: Any]
    else { throw JWS.JWSError.somethingWentWrong }
    jsonObj["alg"] = try jwk.signingAlgorithm().rawValue
    return try JSONSerialization.joseSerialization(withJSONObject: jsonObj)
}
