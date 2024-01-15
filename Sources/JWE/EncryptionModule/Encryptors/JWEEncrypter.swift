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

public protocol JWEEncryptor {
    var supportedKeyManagmentAlgorithms: [KeyManagementAlgorithm] { get }
    var supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm] { get }
    
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK?,
        recipientKey: JWK?,
        protectedHeader: P?,
        unprotectedHeader: U?,
        recipientHeader: R?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data?,
        hasMultiRecipients: Bool
    ) throws -> JWEParts<P, R>
}

public protocol JWEMultiEncryptor {
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK?,
        recipients: [(header: R?, key: JWK)],
        protectedHeader: P?,
        unprotectedHeader: U?,
        cek: Data?,
        initializationVector: Data?,
        additionalAuthenticationData: Data?,
        encryptionModule: JWEEncryptionModule
    ) throws -> [JWEParts<P, R>]
}

extension JWEEncryptor {
    func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        recipientHeader: R? = nil as DefaultJWEHeaderImpl?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        multiRecipients: Bool = false
    ) throws -> JWEParts<P, R> {
        try self.encrypt(
            payload: payload,
            senderKey: senderKey,
            recipientKey: recipientKey,
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            hasMultiRecipients: multiRecipients
        )
    }
}

extension JWEMultiEncryptor {
    public func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: Data,
        senderKey: JWK? = nil,
        recipientsKeys: [JWK],
        protectedHeader: P? = nil as DefaultJWEHeaderImpl?,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        encryptionModule: JWEEncryptionModule = .default
    ) throws -> [JWEParts<P, DefaultJWEHeaderImpl>] {
        try self.encrypt(
            payload: payload,
            senderKey: senderKey,
            recipients: recipientsKeys.map {
                (DefaultJWEHeaderImpl(from: $0), $0)
            },
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData,
            encryptionModule: encryptionModule
        )
    }
}

//extension JWE {
//    /// Computes the JOSE header by merging an array of `JOSEHeader` objects in the given order.
//    /// The order of headers is important as values from later headers in the array
//    /// will overwrite those from earlier headers if they exist.
//    ///
//    /// - Parameter headers: An array of `JOSEHeader` objects.
//    /// - Returns: A single merged `JOSEHeader` object.
//    static func computeJOSEHeader(
//        recipientHeader: JWERegisteredFieldsHeader?,
//        fromKey: JWK?,
//        from header: JWERegisteredFieldsHeader,
//        unprotectedHeader: JWERegisteredFieldsHeader?
//    ) -> JWERegisteredFieldsHeader {
//        var mergedHeader = header
//
//        if let algorithm = recipientHeader?.keyManagementAlgorithm {
//            mergedHeader.keyManagementAlgorithm = algorithm
//        }
//
//        if let jwkSetURL = recipientHeader?.jwkSetURL {
//            mergedHeader.jwkSetURL = jwkSetURL
//        }
//
//        if let jwk = recipientHeader?.jwk {
//            mergedHeader.jwk = jwk
//        }
//
//        if let keyID = recipientHeader?.keyID {
//            mergedHeader.keyID = keyID
//        }
//
//        if let x509URL = recipientHeader?.x509URL {
//            mergedHeader.x509URL = x509URL
//        }
//
//        if let x509CertificateChain = recipientHeader?.x509CertificateChain {
//            mergedHeader.x509CertificateChain = x509CertificateChain
//        }
//
//        if let x509CertificateSHA1Thumbprint = recipientHeader?.x509CertificateSHA1Thumbprint {
//            mergedHeader.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
//        }
//
//        if let x509CertificateSHA256Thumbprint = recipientHeader?.x509CertificateSHA256Thumbprint {
//            mergedHeader.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
//        }
//
//        if let type = recipientHeader?.type {
//            mergedHeader.type = type
//        }
//
//        if let contentType = recipientHeader?.contentType {
//            mergedHeader.contentType = contentType
//        }
//
//        if let initializationVector = recipientHeader?.initializationVector {
//            mergedHeader.initializationVector = initializationVector
//        }
//
//        if let authenticationTag = recipientHeader?.authenticationTag {
//            mergedHeader.authenticationTag = authenticationTag
//        }
//
//        if let ephemeralPublicKey = recipientHeader?.ephemeralPublicKey {
//            mergedHeader.ephemeralPublicKey = ephemeralPublicKey
//        }
//
//        if let agreementPartyUInfo = recipientHeader?.agreementPartyUInfo {
//            mergedHeader.agreementPartyUInfo = agreementPartyUInfo
//        }
//
//        if let agreementPartyVInfo = recipientHeader?.agreementPartyVInfo {
//            mergedHeader.agreementPartyVInfo = agreementPartyVInfo
//        }
//
//        if let pbes2SaltInput = recipientHeader?.pbes2SaltInput {
//            mergedHeader.pbes2SaltInput = pbes2SaltInput
//        }
//
//        if let pbes2Count = recipientHeader?.pbes2SaltCount {
//            mergedHeader.pbes2SaltCount = pbes2Count
//        }
//        
//        if let keyID = fromKey?.keyID {
//            mergedHeader.keyID = keyID
//        }
//
//        if let alg = fromKey?.algorithm, let keyAlg = KeyManagementAlgorithm(rawValue: alg) {
//            mergedHeader.keyManagementAlgorithm = keyAlg
//        }
//        
//        if let url = fromKey?.x509URL {
//            mergedHeader.x509URL = url
//        }
//        
//        if let x509 = fromKey?.x509CertificateChain {
//            mergedHeader.x509CertificateChain = x509
//        }
//        
//        if let x509 = fromKey?.x509CertificateSHA1Thumbprint {
//            mergedHeader.x509CertificateSHA1Thumbprint = x509
//        }
//        
//        if let x509 = fromKey?.x509CertificateSHA256Thumbprint {
//            mergedHeader.x509CertificateSHA256Thumbprint = x509
//        }
//
//        return mergedHeader
//    }
//}
