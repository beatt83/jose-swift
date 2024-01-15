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

func isSupported(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?,
    supportedKeyAlgorithms: [KeyManagementAlgorithm],
    supportedContentEncryptionAlgorithms: [ContentEncryptionAlgorithm]
) -> Bool {
    guard
        let keyAlg = getKeyAlgorithm(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        ),
        let encAlg = getEncoding(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: recipientHeader
        )
    else { return false }
    
    return supportedKeyAlgorithms.contains(keyAlg)
    && supportedContentEncryptionAlgorithms.contains(encAlg)
}

func recipientMatch(
    jwk: JWK?,
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> Bool {
    recipientMatch(jwk: jwk, header: recipientHeader)
    || recipientMatch(jwk: jwk, header: protectedHeader)
    || recipientMatch(jwk: jwk, header: unprotectedHeader)
}

func recipientMatch(
    jwk: JWK?,
    header: JWERegisteredFieldsHeader?
) -> Bool {
    guard let header, let jwk else {
        return false
    }
    if let thumbprint = try? jwk.thumbprint() {
        if thumbprint == header.keyID {
            return true
        }
        
        if
            let hThumbprint = try? header.jwk?.thumbprint(),
            hThumbprint == thumbprint
        {
            return true
        }
    }
    
    if let x509Url = header.x509URL, x509Url == jwk.x509URL { return true }
    if
        let x509CertificateSHA256Thumbprint = header.x509CertificateSHA256Thumbprint,
        x509CertificateSHA256Thumbprint == jwk.x509CertificateSHA256Thumbprint
    { return true }
    
    if
        let x509CertificateSHA1Thumbprint = header.x509CertificateSHA1Thumbprint,
        x509CertificateSHA1Thumbprint == jwk.x509CertificateSHA1Thumbprint
    { return true }
    
    if let keyID = header.keyID, keyID == jwk.keyID { return true }
    
    return false
}
