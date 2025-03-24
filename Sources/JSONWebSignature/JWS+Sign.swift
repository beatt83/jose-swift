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

public enum JWSSignOptions {
    case unencodedPayload
}

extension JWS {
    /// Initializes a new JWS (JSON Web Signature) instance with the given payload, protected header data, and cryptographic key.
    ///
    /// This initializer supports various key types conforming to `KeyRepresentable`, including `Data`, `JWK`, `SecKey`, `CryptoSwift.RSA`,
    /// CryptoKit EC Keys, and Curve25519. When using `Data` as the key type, ensure that the header’s `alg` (algorithm) field is set.
    ///
    /// - Parameters:
    ///   - payload: The data to be signed and included in the JWS.
    ///   - protectedHeaderData: The JSON-encoded data for the protected header.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` or any type conforming to `KeyRepresentable`.
    ///   - options: An optional array of `JWSSignOptions` to customize the signing process.
    /// - Throws: An error if the initialization, header preparation, or signing process fails.
    public init<Key>(payload: Data, protectedHeaderData: Data, key: Key?, options: [JWSSignOptions] = []) throws {
        let signature: Data
        let key = try key.map { try prepareJWK(header: protectedHeaderData, key: $0, isPrivate: true) }
        let (protectedHeader, protectedHeaderData): (DefaultJWSHeaderImpl, Data) = try setHeaderForOptions(
            header: protectedHeaderData,
            options: Set(options)
        )
        if let signer = protectedHeader.algorithm?.cryptoSigner {
            guard let key else {
                throw JWSError.missingKey
            }
            let signingData = try JWS.buildSigningData(header: protectedHeaderData, data: payload)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.protectedHeaderData = protectedHeaderData
        self.protectedHeader = protectedHeader
        self.payload = payload
        self.signature = signature
        self.compactSerialization = try JWS.buildJWSString(header: protectedHeaderData, data: payload, signature: signature)
    }
    
    // Initializes a new `JWS` instance using a protected header, payload data, and a cryptographic key.
    ///
    /// This initializer supports various key types, including `Data` and types conforming to `KeyRepresentable`.
    /// By default, types such as `JWK`, `SecKey`, `CryptoSwift.RSA`, CryptoKit EC Keys, and Curve25519 conform to `KeyRepresentable`
    /// and can be used for signing. When using `Data` as the key type, the header’s `alg` (algorithm) field must be set.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - protectedHeader: The header containing the JWS registered fields.
    ///   - key: The cryptographic key used for signing, which may be of type `Data` or any type conforming to `KeyRepresentable`.
    ///   - options: An optional array of `JWSSignOptions` to further configure the signing process.
    /// - Throws: An error if the signing process fails or if the key is missing.
    public init<Key>(
        payload: Data,
        protectedHeader: JWSRegisteredFieldsHeader,
        key: Key?,
        options: [JWSSignOptions] = []
    ) throws {
        let signature: Data
        let headerData = try JSONEncoder.jose.encode(protectedHeader)
        let (_, protectedHeaderData): (DefaultJWSHeaderImpl, Data) = try setHeaderForOptions(
            header: headerData,
            options: Set(options)
        )
        let key = try key.map { try prepareJWK(header: protectedHeaderData, key: $0, isPrivate: true) }
        if let signer = protectedHeader.algorithm?.cryptoSigner {
            guard let key else {
                throw JWSError.missingKey
            }
            let signingData = try JWS.buildSigningData(header: protectedHeaderData, data: payload)
            signature = try signer.sign(data: signingData, key: key)
        } else {
            signature = Data()
        }
        self.protectedHeaderData = headerData
        self.protectedHeader = protectedHeader
        self.payload = payload
        self.signature = signature
        self.compactSerialization = try JWS.buildJWSString(header: protectedHeaderData, data: payload, signature: signature)
    }
    
    /// Convenience initializer to create a `JWS` instance using payload data and a cryptographic key.
    ///
    /// The signing algorithm is automatically determined from the provided key, and a default header is created based on that algorithm.
    /// This initializer supports various key types conforming to `KeyRepresentable`, including `Data`, `JWK`, `SecKey`, `CryptoSwift.RSA`,
    /// CryptoKit EC Keys, and Curve25519. When using `Data` as the key type, ensure that the header’s `alg` (algorithm) field is set.
    ///
    /// - Parameters:
    ///   - payload: The data to be signed and included in the JWS.
    ///   - key: The cryptographic key used for signing, which can be of type `Data` or any type conforming to `KeyRepresentable`.
    ///   - options: An optional array of `JWSSignOptions` to customize the signing process.
    /// - Throws: An error if the signing process fails or if the key is inappropriate for the determined algorithm.
    public init<Key>(
        payload: Data,
        key: Key,
        options: [JWSSignOptions] = []
    ) throws {
        let jwkKey = try prepareJWK(header: nil, key: key)
        let algorithm = try jwkKey.signingAlgorithm()
        let header = DefaultJWSHeaderImpl(algorithm: algorithm)
        try self.init(payload: payload, protectedHeader: header, key: key, options: options)
    }
    
    /// Generates a JSON serialization of the JWS object with multiple signatures, each corresponding to a different key in the provided array.
    /// This method is used when a payload needs to be signed with multiple keys.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    /// - Returns: A `JWSJson` object representing the signed payload with multiple signatures.
    /// - Throws: An error if the signing process fails.
    static func jsonSerialization(
        payload: Data,
        keys: [KeyRepresentable]
    ) throws -> JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> {
        let signatures = try keys
            .map {
                let key = try $0.jwk
                let jws = try JWS.init(payload: payload, key: $0)
                let header = key.keyID != nil ? DefaultJWSHeaderImpl(from: key) : jws.protectedHeader
                
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
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    /// - Returns: JSON encoded data representing the signed payload with multiple signatures.
    /// - Throws: An error if the JSON encoding process fails.
    public static func jsonSerialization(
        payload: Data,
        keys: [KeyRepresentable]
    ) throws -> Data {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try jsonSerialization(payload: payload, keys: keys)
        return try JSONEncoder.jose.encode(json)
    }
    
    /// Generates a JSON serialization of the JWS object with signatures for a given payload, protected header, header, and keys.
    /// This method allows for specifying custom types for the protected header and header.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload data.
    ///   - protectedHeader: The protected header instance.
    ///   - unprotectedHeader: An optional header instance.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    /// - Returns: A `JWSJson` object with the specified header types.
    /// - Throws: An error if the signing process fails.
    static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        keys: [KeyRepresentable]
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
    
    /// Creates a JSON Web Signature (JWS) object in JSON format using the provided payload, headers, and keys.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be signed and included in the JWS.
    ///   - protectedHeader: The protected header fields conforming to `JWSRegisteredFieldsHeader`.
    ///   - unprotectedHeader: The optional unprotected header fields, defaulting to `nil`.
    ///   - keys: An array of cryptographic keys used for signing, each of which can be of type `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or JSON serialization fails.
    /// - Returns: A `Data` object containing the JSON-encoded JWS.
    public static func jsonSerialization<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        keys: [KeyRepresentable]
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
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The payload data to be signed.
    ///   - key: The cryptographic key used for signing, which can be of type `KeyRepresentable`.
    /// - Returns: Flattened JSON encoded data representing the signed payload.
    /// - Throws: An error if the signing or JSON encoding process fails.
    public static func jsonSerializationFlattened(
        payload: Data,
        key: KeyRepresentable
    ) throws -> Data {
        let json: JWSJson<DefaultJWSHeaderImpl, DefaultJWSHeaderImpl> = try jsonSerialization(payload: payload, keys: [key])
        return try JSONEncoder.jose.encode(json.flattened())
    }
    
    /// Creates a flattened JSON Web Signature (JWS) object in JSON format using the provided payload, headers, and a key.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be signed and included in the JWS.
    ///   - protectedHeader: The protected header fields conforming to `JWSRegisteredFieldsHeader`.
    ///   - unprotectedHeader: The optional unprotected header fields, defaulting to `nil`.
    ///   - key: The cryptographic key used for signing, which can be of type `KeyRepresentable`.
    ///
    /// - Throws: An error if the signing process or JSON serialization fails.
    /// - Returns: A `Data` object containing the flattened JSON-encoded JWS.
    public static func jsonSerializationFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        key: KeyRepresentable
    ) throws -> Data {
        let json: JWSJson<P, H> = try jsonSerialization(
            payload: payload,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            keys: [key]
        )
        
        return try JSONEncoder.jose.encode(json.flattened())
    }
    
    /// Creates a flattened JSON Web Signature (JWS) object using the provided payload, headers, and a key.
    ///
    /// This initializer supports different types for the `KeyRepresentable`.
    /// The following types by default extend `KeyRepresentable` and can be used as the Key `JWK`, `SecKey`, `CryptoSwift.RSA`
    /// and CriptoKit EC Keys and Curve25519.
    ///
    /// - Parameters:
    ///   - payload: The data to be signed and included in the JWS.
    ///   - protectedHeader: The protected header fields conforming to `JWSRegisteredFieldsHeader`.
    ///   - unprotectedHeader: The optional unprotected header fields, defaulting to `nil`.
    ///   - key: The cryptographic key used for signing, which can be of type `Data`, `SecKey`, or `JWK`.
    ///
    /// - Throws: An error if the signing process or JSON serialization fails.
    /// - Returns: A `JWSJsonFlattened` object containing the flattened JSON-encoded JWS.
    public static func jsonSerializationFlattened<P: JWSRegisteredFieldsHeader, H: JWSRegisteredFieldsHeader>(
        payload: Data,
        protectedHeader: P,
        unprotectedHeader: H? = nil as DefaultJWSHeaderImpl?,
        key: KeyRepresentable
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

func setHeaderForOptions<H: JWSRegisteredFieldsHeader>(header: Data, options: Set<JWSSignOptions>) throws  -> (H, Data) {
    var headerChanges = header
    try options.forEach {
        switch $0 {
        case .unencodedPayload:
            headerChanges = try setUnencodedPayloadHeader(header: headerChanges)
        }
    }
    let jwsFieldsHeader = try JSONDecoder.jwt.decode(H.self, from: headerChanges)
    return (jwsFieldsHeader, headerChanges)
}

func setUnencodedPayloadHeader(header: Data) throws -> Data {
    guard
        var json = try JSONSerialization.jsonObject(with: header) as? [String: Any]
    else { throw JWS.JWSError.somethingWentWrong }
    json["b64"] = false
    var newCritical = (json["crit"] as? [String]).map { Set($0) } ?? Set()
    newCritical.insert("b64")
    json["crit"] = Array(newCritical)
    let jsonData = try JSONSerialization.data(withJSONObject: json)
    return jsonData
}

func prepareHeaderForJWK(header: Data, jwk: JWK?) throws -> Data {
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

func prepareJWK<Key>(header: Data?, key: Key, isPrivate: Bool = false) throws -> JWK {
    switch key {
    case let value as Data:
        guard
            let header,
            let jsonObj = try JSONSerialization.jsonObject(with: header) as? [String: Any],
            let algStr = jsonObj["alg"] as? String,
            let signingAlg = SigningAlgorithm(rawValue: algStr)
        else {
            throw JWS.JWSError.missingAlgorithm
        }
        
        switch signingAlg {
        case .HS256:
            return try DataKey(type: .octSequence, isPrivate: false, isKeyAgreement: false, key: value).jwk
        case .HS384:
            return try DataKey(type: .octSequence, isPrivate: false, isKeyAgreement: false, key: value).jwk
        case .HS512:
            return try DataKey(type: .octSequence, isPrivate: false, isKeyAgreement: false, key: value).jwk
        case .RS256:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .RS384:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .RS512:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .ES256:
            return try DataKey(type: .p256, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .ES384:
            return try DataKey(type: .p384, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .ES512:
            return try DataKey(type: .p521, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .ES256K:
            return try DataKey(type: .secp256k1, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .PS256:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .PS384:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .PS512:
            return try DataKey(type: .rsa, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .EdDSA:
            return try DataKey(type: .curve25519, isPrivate: isPrivate, isKeyAgreement: false, key: value).jwk
        case .invalid, .none:
            throw JWS.JWSError.unsupportedAlgorithm(keyType: nil, algorithm: algStr, curve: nil)
        }
    case let value as KeyRepresentable:
        return try value.jwk
    default:
        throw CryptoError.keyFormatNotSupported(format: String(describing: key.self), supportedFormats: ["Data", "KeyRepresentable"])
    }
}
