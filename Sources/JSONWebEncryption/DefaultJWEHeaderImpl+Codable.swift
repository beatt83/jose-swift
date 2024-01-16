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

extension DefaultJWEHeaderImpl: Codable {
    enum CodingKeys: String, CodingKey {
        case keyManagementAlgorithm = "alg"
        case encodingAlgorithm = "enc"
        case compressionAlgorithm = "zip"
        case jwkSetURL = "jku"
        case jwk
        case keyID = "kid"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
        case type = "typ"
        case contentType = "cty"
        case critical = "crit"
        case initializationVector = "iv"
        case authenticationTag = "tag"
        case ephemeralPublicKey = "epk"
        case agreementPartyUInfo = "apu"
        case agreementPartyVInfo = "apv"
        case pbes2SaltInput = "p2s"
        case pbes2Count = "p2c"
        case senderKeyID = "skid"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(keyManagementAlgorithm, forKey: .keyManagementAlgorithm)
        try container.encodeIfPresent(encodingAlgorithm, forKey: .encodingAlgorithm)
        try container.encodeIfPresent(compressionAlgorithm, forKey: .compressionAlgorithm)
        try container.encodeIfPresent(jwkSetURL, forKey: .jwkSetURL)
        try container.encodeIfPresent(jwk, forKey: .jwk)
        try container.encodeIfPresent(keyID, forKey: .keyID)
        try container.encodeIfPresent(x509URL, forKey: .x509URL)
        try container.encodeIfPresent(x509CertificateChain, forKey: .x509CertificateChain)
        try container.encodeIfPresent(x509CertificateSHA1Thumbprint, forKey: .x509CertificateSHA1Thumbprint)
        try container.encodeIfPresent(x509CertificateSHA256Thumbprint, forKey: .x509CertificateSHA256Thumbprint)
        try container.encodeIfPresent(ephemeralPublicKey, forKey: .ephemeralPublicKey)
        try container.encodeIfPresent(type, forKey: .type)
        try container.encodeIfPresent(contentType, forKey: .contentType)
        try container.encodeIfPresent(critical, forKey: .critical)
        try initializationVector.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .initializationVector)
        }
        try authenticationTag.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .authenticationTag)
        }
        try agreementPartyUInfo.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .agreementPartyUInfo)
        }
        try agreementPartyVInfo.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .agreementPartyVInfo)
        }
        try pbes2SaltInput.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .pbes2SaltInput)
        }
        try pbes2SaltCount.map {
            try container.encodeIfPresent(Base64URL.encode($0), forKey: .pbes2Count)
        }
        try container.encodeIfPresent(senderKeyID, forKey: .senderKeyID)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyManagementAlgorithm = try container.decodeIfPresent(KeyManagementAlgorithm.self, forKey: .keyManagementAlgorithm)
        encodingAlgorithm = try container.decodeIfPresent(ContentEncryptionAlgorithm.self, forKey: .encodingAlgorithm)
        compressionAlgorithm = try container.decodeIfPresent(ContentCompressionAlgorithm.self, forKey: .compressionAlgorithm)
        jwkSetURL = try container.decodeIfPresent(String.self, forKey: .jwkSetURL)
        jwk = try container.decodeIfPresent(JWK.self, forKey: .jwk)
        keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
        x509URL = try container.decodeIfPresent(String.self, forKey: .x509URL)
        x509CertificateChain = try container.decodeIfPresent(String.self, forKey: .x509CertificateChain)
        x509CertificateSHA1Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA1Thumbprint)
        x509CertificateSHA256Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA256Thumbprint)
        ephemeralPublicKey = try container.decodeIfPresent(JWK.self, forKey: .ephemeralPublicKey)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
        critical = try container.decodeIfPresent(String.self, forKey: .critical)
        senderKeyID = try container.decodeIfPresent(String.self, forKey: .senderKeyID)
        let initializationVectorBase64Url = try container.decodeIfPresent(String.self, forKey: .initializationVector)
        initializationVector = try initializationVectorBase64Url.map { try Base64URL.decode($0) }
        let autheticationTagBase64Url = try container.decodeIfPresent(String.self, forKey: .authenticationTag)
        authenticationTag = try autheticationTagBase64Url.map { try Base64URL.decode($0) }
        let partyUInfoBase64Url = try container.decodeIfPresent(String.self, forKey: .agreementPartyUInfo)
        agreementPartyUInfo = try partyUInfoBase64Url.map { try Base64URL.decode($0) }
        let partyVInfoBase64Url = try container.decodeIfPresent(String.self, forKey: .agreementPartyVInfo)
        agreementPartyVInfo = try partyVInfoBase64Url.map { try Base64URL.decode($0) }
        let pbes2SaltInputBase64Url = try container.decodeIfPresent(String.self, forKey: .pbes2SaltInput)
        pbes2SaltInput = try pbes2SaltInputBase64Url.map { try Base64URL.decode($0) }
        let pbes2SaltCountBase64Url = try container.decodeIfPresent(String.self, forKey: .initializationVector)
        pbes2SaltCount = try pbes2SaltCountBase64Url.map { try Base64URL.decode($0) }
    }
}
