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
import Crypto
import SwiftASN1

// MARK: - Supporting Types for DER Decoding

//// Represents the PKCS#8 PrivateKeyInfo structure as defined in [RFC 5208](https://tools.ietf.org/html/rfc5208).
///
/// PrivateKeyInfo ::= SEQUENCE {
///   version                 INTEGER,
///   privateKeyAlgorithm     AlgorithmIdentifier,
///   privateKey              OCTET STRING,
///   attributes              [0] IMPLICIT SET OF Attribute OPTIONAL }
public struct PrivateKeyInfo: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The version number.
    public let version: Int
    /// The algorithm identifier for the private key.
    public let privateKeyAlgorithm: AlgorithmIdentifier
    /// The private key encoded as an octet string.
    public let privateKey: ASN1OctetString
    /// Optional attributes associated with the private key.
    public let attributes: [ASN1Any]?
    
    /// Creates a new PrivateKeyInfo instance.
    ///
    /// - Parameters:
    ///   - version: The version number.
    ///   - privateKeyAlgorithm: The algorithm identifier.
    ///   - privateKey: The private key as an octet string.
    ///   - attributes: Optional attributes.
    public init(
        version: Int,
        privateKeyAlgorithm: AlgorithmIdentifier,
        privateKey: ASN1OctetString,
        attributes: [ASN1Any]?
    ) {
        self.version = version
        self.privateKeyAlgorithm = privateKeyAlgorithm
        self.privateKey = privateKey
        self.attributes = attributes
    }
    
    /// Decodes a PrivateKeyInfo from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The root ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if the DER decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes, withIdentifier: .integer)
            let privateKeyAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes, withIdentifier: .sequence)
            let privateKey = try ASN1OctetString(derEncoded: &nodes, withIdentifier: .octetString)
            let attributes: [ASN1Any]? = try {
                var attrs: [ASN1Any] = []
                // Continue decoding until no nodes remain.
                while let nextNode = nodes.next() {
                    switch nextNode {
                    case let node as DERImplicitlyTaggable:
                        let attr = try ASN1Any(erasing: node, withIdentifier: nextNode.identifier)
                        attrs.append(attr)
                    default:
                        let attr = ASN1Any(derEncoded: nextNode)
                        attrs.append(attr)
                    }
                }
                return attrs.isEmpty ? nil : attrs
            }()
            return PrivateKeyInfo(version: version,
                                  privateKeyAlgorithm: privateKeyAlgorithm,
                                  privateKey: privateKey,
                                  attributes: attributes)
        }
    }
    
    /// Serializes this PrivateKeyInfo into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer to append the encoded data to.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version, explicitlyTaggedWithIdentifier: .integer)
            try coder.serialize(self.privateKeyAlgorithm, explicitlyTaggedWithIdentifier: .sequence)
            try coder.serialize(self.privateKey, explicitlyTaggedWithIdentifier: .octetString)
            if let attrs = self.attributes {
                for attr in attrs {
                    try coder.serialize(attr)
                }
            }
        }
    }
}

/// Represents the SEC1 ECPrivateKey structure as defined in [SEC1](https://www.secg.org/sec1-v2.pdf).
///
/// SEC1 ECPrivateKey ::= SEQUENCE {
///    version        INTEGER,  -- should be 1
///    privateKey     OCTET STRING,
///    parameters [0] EXPLICIT OPTIONAL,
///    publicKey  [1] EXPLICIT OPTIONAL BIT STRING }
public struct ECPrivateKey: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The version number.
    public let version: Int
    /// The private key data as an array slice of bytes.
    public let privateKey: ArraySlice<UInt8>
    /// Optional parameters (often containing the curve information).
    public let parameters: ASN1Any?
    /// Optional public key corresponding to the private key.
    public let publicKey: ASN1BitString?
    
    /// Creates an ECPrivateKey instance.
    ///
    /// - Parameters:
    ///   - version: The version number.
    ///   - privateKey: The private key data.
    ///   - parameters: Optional curve parameters.
    ///   - publicKey: Optional public key.
    public init(
        version: Int,
        privateKey: ArraySlice<UInt8>,
        parameters: ASN1Any?,
        publicKey: ASN1BitString?
    ) {
        self.version = version
        self.privateKey = privateKey
        self.parameters = parameters
        self.publicKey = publicKey
    }
    
    /// Decodes an ECPrivateKey from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The root ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes, withIdentifier: .integer)
            let privateKeyOctet = try ASN1OctetString(derEncoded: &nodes, withIdentifier: .octetString)
            let privateKey = privateKeyOctet.bytes
            let parameters = try? ASN1Any(derEncoded: &nodes)
            let publicKey = try? ASN1BitString(derEncoded: &nodes)
            return ECPrivateKey(version: version,
                                privateKey: privateKey,
                                parameters: parameters,
                                publicKey: publicKey)
        }
    }
    
    /// Serializes this ECPrivateKey into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version, explicitlyTaggedWithIdentifier: .integer)
            try coder.serialize(self.privateKey, explicitlyTaggedWithIdentifier: .octetString)
            if let params = self.parameters {
                try coder.serialize(params)
            }
            if let pubKey = self.publicKey {
                try coder.serialize(pubKey, explicitlyTaggedWithIdentifier: .bitString)
            }
        }
    }
}

/// Represents the PKCS#1 RSAPrivateKey structure as defined in [PKCS#1](https://tools.ietf.org/html/rfc8017).
///
/// RSAPrivateKey ::= SEQUENCE {
///   version           INTEGER,
///   modulus           INTEGER,  -- n
///   publicExponent    INTEGER,  -- e
///   privateExponent   INTEGER,  -- d
///   prime1            INTEGER,  -- p
///   prime2            INTEGER,  -- q
///   exponent1         INTEGER,  -- d mod (p-1)
///   exponent2         INTEGER,  -- d mod (q-1)
///   coefficient       INTEGER   -- (inverse of q) mod p }
public struct RSAPrivateKey: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The version number.
    public let version: Int
    /// The modulus (n).
    public let modulus: ArraySlice<UInt8>
    /// The public exponent (e).
    public let publicExponent: ArraySlice<UInt8>
    /// The private exponent (d).
    public let privateExponent: ArraySlice<UInt8>
    /// The first prime factor (p).
    public let prime1: ArraySlice<UInt8>
    /// The second prime factor (q).
    public let prime2: ArraySlice<UInt8>
    /// The exponent d mod (p-1).
    public let exponent1: ArraySlice<UInt8>
    /// The exponent d mod (q-1).
    public let exponent2: ArraySlice<UInt8>
    /// The coefficient (inverse of q mod p).
    public let coefficient: ArraySlice<UInt8>
    
    /// Creates an RSAPrivateKey instance.
    public init(
        version: Int,
        modulus: ArraySlice<UInt8>,
        publicExponent: ArraySlice<UInt8>,
        privateExponent: ArraySlice<UInt8>,
        prime1: ArraySlice<UInt8>,
        prime2: ArraySlice<UInt8>,
        exponent1: ArraySlice<UInt8>,
        exponent2: ArraySlice<UInt8>,
        coefficient: ArraySlice<UInt8>
    ) {
        self.version = version
        self.modulus = modulus
        self.publicExponent = publicExponent
        self.privateExponent = privateExponent
        self.prime1 = prime1
        self.prime2 = prime2
        self.exponent1 = exponent1
        self.exponent2 = exponent2
        self.coefficient = coefficient
    }
    
    /// Decodes an RSAPrivateKey from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes, withIdentifier: .integer)
            let modulus = try ArraySlice<UInt8>(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let privateExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let coefficient = try ArraySlice<UInt8>(derEncoded: &nodes)
            return RSAPrivateKey(version: version,
                                 modulus: modulus,
                                 publicExponent: publicExponent,
                                 privateExponent: privateExponent,
                                 prime1: prime1,
                                 prime2: prime2,
                                 exponent1: exponent1,
                                 exponent2: exponent2,
                                 coefficient: coefficient)
        }
    }
    
    /// Serializes this RSAPrivateKey into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version, explicitlyTaggedWithIdentifier: .integer)
            try coder.serialize(self.modulus)
            try coder.serialize(self.publicExponent)
            try coder.serialize(self.privateExponent)
            try coder.serialize(self.prime1)
            try coder.serialize(self.prime2)
            try coder.serialize(self.exponent1)
            try coder.serialize(self.exponent2)
            try coder.serialize(self.coefficient)
        }
    }
}

/// Represents a minimal PKCS#1 RSAPublicKey structure.
///
/// RSAPublicKey ::= SEQUENCE {
///     modulus         INTEGER,
///     publicExponent  INTEGER }
public struct RSAPublicKey: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The modulus.
    public let modulus: ArraySlice<UInt8>
    /// The public exponent.
    public let exponent: ArraySlice<UInt8>
    
    /// Creates an RSAPublicKey instance.
    public init(modulus: ArraySlice<UInt8>, exponent: ArraySlice<UInt8>) {
        self.modulus = modulus
        self.exponent = exponent
    }
    
    /// Decodes an RSAPublicKey from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let modulus = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            return RSAPublicKey(modulus: modulus, exponent: exponent)
        }
    }
    
    /// Serializes this RSAPublicKey into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.modulus)
            try coder.serialize(self.exponent)
        }
    }
}

/// Represents an AlgorithmIdentifier as defined in X.509 and used in PKCS structures.
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,
///     parameters  ANY OPTIONAL }
public struct AlgorithmIdentifier: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The algorithm OID.
    public let algorithm: ASN1ObjectIdentifier
    /// Optional parameters associated with the algorithm.
    public let parameters: ASN1Any?
    
    /// Creates a new AlgorithmIdentifier.
    public init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Any?) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    /// Decodes an AlgorithmIdentifier from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let parameters = try? ASN1Any(derEncoded: &nodes)
            return AlgorithmIdentifier(algorithm: algorithm, parameters: parameters)
        }
    }
    
    /// Serializes this AlgorithmIdentifier into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            if let params = self.parameters {
                try coder.serialize(params)
            }
        }
    }
}

/// Represents the SubjectPublicKeyInfo container as defined in [X.509](https://tools.ietf.org/html/rfc5280).
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm            AlgorithmIdentifier,
///   subjectPublicKey     BIT STRING }
public struct SubjectPublicKeyInfo: DERImplicitlyTaggable {
    public static var defaultIdentifier: ASN1Identifier { .sequence }
    
    /// The algorithm identifier.
    public let algorithm: AlgorithmIdentifier
    /// The subject public key encoded as a BIT STRING.
    public let subjectPublicKey: ASN1BitString
    
    /// Creates a new SubjectPublicKeyInfo instance.
    public init(algorithm: AlgorithmIdentifier, subjectPublicKey: ASN1BitString) {
        self.algorithm = algorithm
        self.subjectPublicKey = subjectPublicKey
    }
    
    /// Decodes a SubjectPublicKeyInfo from a DER-encoded ASN1Node.
    ///
    /// - Parameters:
    ///   - rootNode: The ASN1Node containing the DER encoding.
    ///   - identifier: The expected ASN1Identifier.
    /// - Throws: An error if decoding fails.
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try AlgorithmIdentifier(derEncoded: &nodes, withIdentifier: .sequence)
            let subjectPublicKey = try ASN1BitString(derEncoded: &nodes, withIdentifier: .bitString)
            return SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: subjectPublicKey)
        }
    }
    
    /// Serializes this SubjectPublicKeyInfo into a DER stream.
    ///
    /// - Parameters:
    ///   - coder: The DER serializer.
    ///   - identifier: The ASN1Identifier for the constructed node.
    /// - Throws: An error if serialization fails.
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm, explicitlyTaggedWithIdentifier: .sequence)
            try coder.serialize(self.subjectPublicKey, explicitlyTaggedWithIdentifier: .bitString)
        }
    }
}

// MARK: - JWK Initialization from PEM using swift‑asn1

public extension JWK {
    /// Initializes a JSON Web Key (JWK) from a PEM-encoded string.
    ///
    /// This initializer supports both public and private keys.
    /// - For public keys, the PEM must be in SubjectPublicKeyInfo format.
    /// - For private keys, the PEM can be in either PKCS#8 format or legacy formats:
    ///   - "EC PRIVATE KEY" for SEC1 EC private keys.
    ///   - "RSA PRIVATE KEY" for PKCS#1 RSA private keys.
    ///
    /// During initialization, the PEM is parsed and the corresponding ASN.1 structure is decoded.
    ///
    /// - Parameter pem: The PEM-encoded key string.
    /// - Throws: An error if the PEM decoding or ASN.1 parsing fails.
    init(pem: String) throws {
        // If the PEM string contains "EC PRIVATE KEY", parse it as a SEC1 EC private key.
        if pem.contains("EC PRIVATE KEY") {
            let pemDocument = try PEMDocument(pemString: pem)
            let derBytes = pemDocument.derBytes
            let ecPrivateKey = try ECPrivateKey(derEncoded: ArraySlice(derBytes), withIdentifier: .sequence)
            
            let x: Data?
            let y: Data?
            if let pubKeyBitString = ecPrivateKey.publicKey {
                var rawKeyBytes = pubKeyBitString.bytes
                if let first = rawKeyBytes.first, first == 0x00 {
                    rawKeyBytes = rawKeyBytes.dropFirst()
                }
                guard rawKeyBytes.first == 0x04 else {
                    throw JWK.Error.pemDecodingError
                }
                let coordinateLength = (rawKeyBytes.count - 1) / 2
                x = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1)..<rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)])
                y = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)..<rawKeyBytes.endIndex])
            } else {
                x = nil
                y = nil
            }
            
            var curve: CryptographicCurve? = nil
            if let params = ecPrivateKey.parameters {
                var serializer = DER.Serializer()
                try params.serialize(into: &serializer)
                let paramsBytes = serializer.serializedBytes
                let namedCurveOID: ASN1ObjectIdentifier = try {
                    let outerNode = try DER.parse(ArraySlice(paramsBytes))
                    guard outerNode.identifier.tagClass == .contextSpecific,
                          outerNode.identifier.tagNumber == 0,
                          case .constructed(let children) = outerNode.content,
                          Array(children).count == 1,
                          let innerNode = Array(children).first else {
                        throw ASN1Error.invalidASN1Object(reason: "Expected parameters as an explicitly tagged [0] object containing an OID")
                    }
                    return try ASN1ObjectIdentifier(derEncoded: innerNode, withIdentifier: .objectIdentifier)
                }()
                curve = JWK.mapCurveOID(namedCurveOID.description)
            }
            
            self.init(
                keyType: .ellipticCurve,
                curve: curve,
                x: x,
                y: y,
                d: Data(ecPrivateKey.privateKey)
            )
        } else if pem.contains("RSA PRIVATE KEY") {
            // Parse as a PKCS#1 RSA private key.
            let pemDocument = try PEMDocument(pemString: pem)
            let derBytes = pemDocument.derBytes
            let rsaPrivateKey = try RSAPrivateKey(derEncoded: ArraySlice(derBytes), withIdentifier: .sequence)
            self.init(
                keyType: .rsa,
                e: Data(rsaPrivateKey.publicExponent),
                p: Data(rsaPrivateKey.prime1),
                q: Data(rsaPrivateKey.prime2),
                n: Data(rsaPrivateKey.modulus),
                dp: Data(rsaPrivateKey.exponent1),
                dq: Data(rsaPrivateKey.exponent2),
                qi: Data(rsaPrivateKey.coefficient),
                d: Data(rsaPrivateKey.privateExponent)
            )
        } else if pem.contains("PRIVATE KEY") {
            // Parse as a PKCS#8 formatted private key.
            let pemDocument = try PEMDocument(pemString: pem)
            let derBytes = pemDocument.derBytes
            let pkcs8 = try PrivateKeyInfo(derEncoded: ArraySlice(derBytes), withIdentifier: .sequence)
            
            if pkcs8.privateKeyAlgorithm.algorithm == ASN1ObjectIdentifier("1.2.840.10045.2.1") {
                // PKCS#8 EC private key. The OCTET STRING contains a SEC1 ECPrivateKey.
                let ecPrivData = Data(pkcs8.privateKey.bytes)
                let ecPrivateKey = try ECPrivateKey(derEncoded: ArraySlice(ecPrivData), withIdentifier: .sequence)
                
                guard let pubKeyBitString = ecPrivateKey.publicKey else {
                    throw JWK.Error.pemDecodingError
                }
                var rawKeyBytes = pubKeyBitString.bytes
                if let first = rawKeyBytes.first, first == 0x00 {
                    rawKeyBytes = rawKeyBytes.dropFirst()
                }
                guard rawKeyBytes.first == 0x04 else {
                    throw JWK.Error.pemDecodingError
                }
                let coordinateLength = (rawKeyBytes.count - 1) / 2
                let x = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1)..<rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)])
                let y = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)..<rawKeyBytes.endIndex])
                
                var curve: CryptographicCurve? = nil
                if let params = pkcs8.privateKeyAlgorithm.parameters {
                    var serializer = DER.Serializer()
                    try params.serialize(into: &serializer)
                    let paramsBytes = serializer.serializedBytes
                    let curveOID = try ASN1ObjectIdentifier(derEncoded: ArraySlice(paramsBytes), withIdentifier: .objectIdentifier)
                    curve = JWK.mapCurveOID(curveOID.description)
                }
                
                self.init(
                    keyType: .ellipticCurve,
                    curve: curve,
                    x: x,
                    y: y,
                    d: Data(ecPrivateKey.privateKey)
                )
            } else if pkcs8.privateKeyAlgorithm.algorithm == ASN1ObjectIdentifier("1.2.840.113549.1.1.1") {
                // PKCS#8 RSA private key.
                let rsaPrivData = Data(pkcs8.privateKey.bytes)
                let rsaPrivateKey = try RSAPrivateKey(derEncoded: ArraySlice(rsaPrivData), withIdentifier: .sequence)
                self.init(
                    keyType: .rsa,
                    e: Data(rsaPrivateKey.publicExponent),
                    p: Data(rsaPrivateKey.prime1),
                    q: Data(rsaPrivateKey.prime2),
                    n: Data(rsaPrivateKey.modulus),
                    dp: Data(rsaPrivateKey.exponent1),
                    dq: Data(rsaPrivateKey.exponent2),
                    qi: Data(rsaPrivateKey.coefficient),
                    d: Data(rsaPrivateKey.privateExponent)
                )
            } else {
                throw JWK.Error.pemDecodingError
            }
        } else {
            // Otherwise, assume a public key in SubjectPublicKeyInfo format.
            let pemDocument = try PEMDocument(pemString: pem)
            let derBytes = pemDocument.derBytes
            let spki = try SubjectPublicKeyInfo(derEncoded: ArraySlice(derBytes), withIdentifier: .sequence)
            
            if spki.algorithm.algorithm == ASN1ObjectIdentifier("1.2.840.10045.2.1") {
                var curve: CryptographicCurve? = nil
                if let params = spki.algorithm.parameters {
                    var serializer = DER.Serializer()
                    try params.serialize(into: &serializer)
                    let paramsBytes = serializer.serializedBytes
                    let curveOID = try ASN1ObjectIdentifier(derEncoded: ArraySlice(paramsBytes), withIdentifier: .objectIdentifier)
                    curve = JWK.mapCurveOID(curveOID.description)
                }
                var rawKeyBytes = spki.subjectPublicKey.bytes
                if let first = rawKeyBytes.first, first == 0x00 {
                    rawKeyBytes = rawKeyBytes.dropFirst()
                }
                guard rawKeyBytes.first == 0x04 else {
                    throw JWK.Error.pemDecodingError
                }
                let coordinateLength = (rawKeyBytes.count - 1) / 2
                let x = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1)..<rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)])
                let y = Data(rawKeyBytes[rawKeyBytes.index(rawKeyBytes.startIndex, offsetBy: 1+coordinateLength)..<rawKeyBytes.endIndex])
                self.init(
                    keyType: .ellipticCurve,
                    curve: curve,
                    x: x,
                    y: y
                )
            } else if spki.algorithm.algorithm == ASN1ObjectIdentifier("1.2.840.113549.1.1.1") {
                let rsaKeyBytes = spki.subjectPublicKey.bytes
                let rsaPublicKey = try RSAPublicKey(derEncoded: ArraySlice(rsaKeyBytes), withIdentifier: .sequence)
                self.init(
                    keyType: .rsa,
                    e: Data(rsaPublicKey.exponent),
                    n: Data(rsaPublicKey.modulus)
                )
            } else {
                throw JWK.Error.pemDecodingError
            }
        }
    }
    
    /// Maps a curve OID string to a CryptographicCurve value.
    ///
    /// - Parameter oid: The string representation of the curve OID.
    /// - Returns: The corresponding CryptographicCurve, if recognized.
    private static func mapCurveOID(_ oid: String) -> CryptographicCurve? {
        switch oid {
        case "1.2.840.10045.3.1.7":
            return .p256
        case "1.3.132.0.34":
            return .p384
        case "1.3.132.0.35":
            return .p521
        case "1.3.132.0.10":
            return .secp256k1
        default:
            return nil
        }
    }
}
