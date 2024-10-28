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

/// `JWSProtectedFieldsHeader` protocol defines the structure for the protected header fields used in a JSON Web Signature (JWS).
/// It includes various optional fields that can be included in a JWS Header.
public protocol JWSRegisteredFieldsHeader: Codable, Sendable {
    /// The signing algorithm to be used.
    var algorithm: SigningAlgorithm? { get set }

    /// URL that refers to a resource for a set of JSON-encoded public keys.
    var jwkSetURL: String? { get set }

    /// JSON Web Key representing the key used to sign the payload.
    var jwk: JWK? { get set }

    /// Key ID hint indicating which key was used to secure the JWS.
    var keyID: String? { get set }

    /// URL for the X.509 public key certificate or certificate chain corresponding to the key used to sign the JWS.
    var x509URL: String? { get set }

    /// X.509 public key certificate or certificate chain.
    var x509CertificateChain: [String]? { get set }

    /// Base64URL-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    var x509CertificateSHA1Thumbprint: String? { get set }

    /// Base64URL-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
    var x509CertificateSHA256Thumbprint: String? { get set }

    /// Type of token - typically used to declare a MIME type.
    var type: String? { get set }

    /// Media type of the complete JWS.
    var contentType: String? { get set }

    /// Indicates extensions to this protocol that must be understood and processed.
    var critical: [String]? { get set }
    
    var base64EncodedUrlPayload: Bool? { get set }
}

/// `DefaultJWSHeaderImpl` is a default implementation of the `JWSProtectedFieldsHeader` protocol.
/// It provides storage for the common fields found in a JWS protected header.
public struct DefaultJWSHeaderImpl: JWSRegisteredFieldsHeader {
    public var algorithm: SigningAlgorithm?
    public var keyID: String?
    public var jwkSetURL: String?
    public var jwk: JWK?
    public var x509URL: String?
    public var x509CertificateChain: [String]?
    public var x509CertificateSHA1Thumbprint: String?
    public var x509CertificateSHA256Thumbprint: String?
    public var type: String?
    public var contentType: String?
    public var critical: [String]?
    public var base64EncodedUrlPayload: Bool?
    
    /// Initializes a new `DefaultJWSHeaderImpl` instance with optional parameters for each field.
    /// - Parameters:
    ///   - algorithm: The signing algorithm to be used (optional).
    ///   - keyID: The Key ID hint (optional).
    ///   - jwkSetURL: The URL for a set of JSON-encoded public keys (optional).
    ///   - jwk: The JSON Web Key (optional).
    ///   - x509URL: The URL for the X.509 public key certificate or certificate chain (optional).
    ///   - x509CertificateChain: The X.509 public key certificate or certificate chain (optional).
    ///   - x509CertificateSHA1Thumbprint: The SHA-1 thumbprint of the X.509 certificate (optional).
    ///   - x509CertificateSHA256Thumbprint: The SHA-256 thumbprint of the X.509 certificate (optional).
    ///   - type: The type of token (optional).
    ///   - contentType: The media type of the complete JWS (optional).
    ///   - critical: Indications of extensions that must be understood and processed (optional).
    public init(
        algorithm: SigningAlgorithm? = nil,
        keyID: String? = nil,
        jwkSetURL: String? = nil,
        jwk: JWK? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
        type: String? = nil,
        contentType: String? = nil,
        critical: [String]? = nil,
        base64EncodedUrlPayload: Bool? = nil
    ) {
        self.algorithm = algorithm
        self.keyID = keyID
        self.jwkSetURL = jwkSetURL
        self.jwk = jwk
        self.x509URL = x509URL
        self.x509CertificateChain = x509CertificateChain
        self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
        self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
        self.type = type
        self.contentType = contentType
        self.critical = critical
        self.base64EncodedUrlPayload = base64EncodedUrlPayload
    }
    
    public init(from: JWK) {
        self.init(
            keyID: from.keyID,
            x509URL: from.x509URL,
            x509CertificateChain: from.x509CertificateChain,
            x509CertificateSHA1Thumbprint: from.x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint: from.x509CertificateSHA256Thumbprint
        )
    }
}
