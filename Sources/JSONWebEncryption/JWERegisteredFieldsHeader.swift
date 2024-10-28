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

/// `JWERegisteredFieldsHeader` protocol defines the standard fields used in the header of a JSON Web Encryption (JWE) object.
/// It includes fields for specifying algorithms, keys, and other metadata related to JWE.
public protocol JWERegisteredFieldsHeader: JWARegisteredFieldsHeader, Sendable {
    /// The algorithm used for key management in the JWE process.
    var keyManagementAlgorithm: KeyManagementAlgorithm? { get set }

    /// The algorithm used for encoding the content in the JWE process.
    var encodingAlgorithm: ContentEncryptionAlgorithm? { get set }

    /// The compression algorithm used, if any, for compressing the payload before encryption.
    var compressionAlgorithm: ContentCompressionAlgorithm? { get set }

    /// URL pointing to a set of JSON-encoded public keys for key discovery.
    var jwkSetURL: String? { get set }

    /// JSON Web Key representing the key used to encrypt or validate the JWE payload.
    var jwk: JWK? { get set }

    /// Identifier for the key used in the JWE process, facilitating key selection.
    var keyID: String? { get set }

    /// URL pointing to an X.509 public key certificate or certificate chain.
    var x509URL: String? { get set }

    /// X.509 public key certificate or certificate chain in string format.
    var x509CertificateChain: [String]? { get set }

    /// Base64URL-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate, used for key identification.
    var x509CertificateSHA1Thumbprint: String? { get set }

    /// Base64URL-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
    var x509CertificateSHA256Thumbprint: String? { get set }

    /// Type of the token, typically used to declare a MIME type.
    var type: String? { get set }

    /// Media type of the complete JWE, describing the payload content type.
    var contentType: String? { get set }

    /// List of critical headers that must be understood and processed.
    var critical: [String]? { get set }

    /// Key ID of the sender's key, used in the `ECDH-1PU` key agreement algorithm.
    var senderKeyID: String? { get set }

    /// Initializes a new header with the specified parameters.
    /// - Parameters:
    ///   - keyManagementAlgorithm: Algorithm used for key management.
    ///   - encodingAlgorithm: Algorithm used for content encryption.
    ///   - compressionAlgorithm: Optional compression algorithm.
    ///   - keyID: Optional identifier for the key.
    ///   - jwkSetURL: Optional URL for the JSON Web Key Set.
    ///   - jwk: Optional JSON Web Key.
    ///   - x509URL: Optional URL for X.509 public key certificate.
    ///   - x509CertificateChain: Optional X.509 certificate chain.
    ///   - x509CertificateSHA1Thumbprint: Optional SHA-1 thumbprint of X.509 certificate.
    ///   - x509CertificateSHA256Thumbprint: Optional SHA-256 thumbprint of X.509 certificate.
    ///   - type: Optional type of the token.
    ///   - contentType: Optional content type of the JWE.
    ///   - critical: Optional list of critical headers.
    ///   - senderKeyId: Optional Key ID of the sender's key.
    init(
        keyManagementAlgorithm: KeyManagementAlgorithm?,
        encodingAlgorithm: ContentEncryptionAlgorithm?,
        compressionAlgorithm: ContentCompressionAlgorithm?,
        keyID: String?,
        jwkSetURL: String?,
        jwk: JWK?,
        x509URL: String?,
        x509CertificateChain: [String]?,
        x509CertificateSHA1Thumbprint: String?,
        x509CertificateSHA256Thumbprint: String?,
        type: String?,
        contentType: String?,
        critical: [String]?,
        ephemeralPublicKey: JWK?,
        agreementPartyUInfo: Data?,
        agreementPartyVInfo: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        pbes2SaltInput: Data?,
        pbes2SaltCount: Int?,
        senderKeyId: String?
    )
}

extension JWERegisteredFieldsHeader {
    public init(
        keyManagementAlgorithm: KeyManagementAlgorithm? = nil,
        encodingAlgorithm: ContentEncryptionAlgorithm? = nil,
        compressionAlgorithm: ContentCompressionAlgorithm? = nil,
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
        ephemeralPublicKey: JWK? = nil,
        agreementPartyUInfo: Data? = nil,
        agreementPartyVInfo: Data? = nil,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        pbes2SaltInput: Data? = nil,
        pbes2SaltCount: Int? = nil,
        senderKeyId: String? = nil
    ) {
        self.init(
            keyManagementAlgorithm: keyManagementAlgorithm,
            encodingAlgorithm: encodingAlgorithm,
            compressionAlgorithm: compressionAlgorithm,
            keyID: keyID,
            jwkSetURL: jwkSetURL,
            jwk: jwk,
            x509URL: x509URL,
            x509CertificateChain: x509CertificateChain,
            x509CertificateSHA1Thumbprint: x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint: x509CertificateSHA256Thumbprint,
            type: type,
            contentType: contentType,
            critical: critical,
            ephemeralPublicKey: ephemeralPublicKey,
            agreementPartyUInfo: agreementPartyUInfo,
            agreementPartyVInfo: agreementPartyVInfo,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            pbes2SaltInput: pbes2SaltInput,
            pbes2SaltCount: pbes2SaltCount,
            senderKeyId: senderKeyId
        )
    }
    
    init(from: JWERegisteredFieldsHeader) {
        self.init(
            keyManagementAlgorithm: from.keyManagementAlgorithm,
            encodingAlgorithm: from.encodingAlgorithm,
            compressionAlgorithm: from.compressionAlgorithm,
            keyID: from.keyID,
            jwkSetURL: from.jwkSetURL,
            jwk: from.jwk,
            x509URL: from.x509URL,
            x509CertificateChain: from.x509CertificateChain,
            x509CertificateSHA1Thumbprint: from.x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint: from.x509CertificateSHA256Thumbprint,
            type: from.type,
            contentType: from.contentType,
            critical: from.critical,
            ephemeralPublicKey: from.ephemeralPublicKey,
            agreementPartyUInfo: from.agreementPartyUInfo,
            agreementPartyVInfo: from.agreementPartyVInfo,
            initializationVector: from.initializationVector,
            authenticationTag: from.authenticationTag,
            pbes2SaltInput: from.pbes2SaltInput,
            pbes2SaltCount: from.pbes2SaltCount,
            senderKeyId: from.senderKeyID
        )
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
    
    init(key: JWK, header: JWERegisteredFieldsHeader) {
        self.init(
            keyManagementAlgorithm: header.keyManagementAlgorithm,
            encodingAlgorithm: header.encodingAlgorithm,
            keyID: key.keyID,
            jwkSetURL: header.jwkSetURL,
            jwk: header.jwk,
            x509URL: key.x509URL,
            x509CertificateChain: key.x509CertificateChain,
            x509CertificateSHA1Thumbprint: key.x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint: key.x509CertificateSHA256Thumbprint,
            ephemeralPublicKey: header.ephemeralPublicKey,
            agreementPartyUInfo: header.agreementPartyUInfo,
            agreementPartyVInfo: header.agreementPartyVInfo,
            initializationVector: header.initializationVector,
            authenticationTag: header.authenticationTag,
            pbes2SaltInput: header.pbes2SaltInput,
            pbes2SaltCount: header.pbes2SaltCount,
            senderKeyId: header.senderKeyID
        )
    }
}

/// `DefaultJWEHeaderImpl` is a default implementation of the `JWERegisteredFieldsHeader` protocol.
/// It provides properties to specify various parameters and algorithms used in the JSON Web Encryption (JWE) process.
public struct DefaultJWEHeaderImpl: JWERegisteredFieldsHeader {
    public var keyManagementAlgorithm: KeyManagementAlgorithm?
    public var encodingAlgorithm: ContentEncryptionAlgorithm?
    public var compressionAlgorithm: ContentCompressionAlgorithm?
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
    public var ephemeralPublicKey: JWK?
    public var agreementPartyUInfo: Data?
    public var agreementPartyVInfo: Data?
    public var initializationVector: Data?
    public var authenticationTag: Data?
    public var pbes2SaltInput: Data?
    public var pbes2SaltCount: Int?
    public var senderKeyID: String?
    
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
        keyManagementAlgorithm: KeyManagementAlgorithm?,
        encodingAlgorithm: ContentEncryptionAlgorithm?,
        compressionAlgorithm: ContentCompressionAlgorithm?,
        keyID: String?,
        jwkSetURL: String?,
        jwk: JWK?,
        x509URL: String?,
        x509CertificateChain: [String]?,
        x509CertificateSHA1Thumbprint: String?,
        x509CertificateSHA256Thumbprint: String?,
        type: String?,
        contentType: String?,
        critical: [String]?,
        ephemeralPublicKey: JWK?,
        agreementPartyUInfo: Data?,
        agreementPartyVInfo: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        pbes2SaltInput: Data?,
        pbes2SaltCount: Int?,
        senderKeyId: String?
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.encodingAlgorithm = encodingAlgorithm
        self.compressionAlgorithm = compressionAlgorithm
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
        self.ephemeralPublicKey = ephemeralPublicKey
        self.agreementPartyUInfo = agreementPartyUInfo
        self.agreementPartyVInfo = agreementPartyVInfo
        self.initializationVector = initializationVector
        self.authenticationTag = authenticationTag
        self.pbes2SaltInput = pbes2SaltInput
        self.pbes2SaltCount = pbes2SaltCount
        self.senderKeyID = senderKeyId
    }
}
