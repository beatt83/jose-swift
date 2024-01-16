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

extension JWE {
    /// Initializes a `JWE` object from a compact serialization string.
    /// This method decodes the serialized string into its respective components.
    /// - Parameters:
    ///   - compactString: The compact serialization string of the JWE.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Throws: `JWEError.invalidJWECompactString` if the compact string format is invalid.
    public init(
        compactString: String,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws {
        let components = compactString.components(separatedBy: ".")
        guard components.count == 5 else {
            throw JWEError.invalidJWECompactString
        }
        
        try self.init(
            protectedHeader: Base64URL.decode(components[0]),
            encryptedKey: Base64URL.decode(components[1]),
            initializationVector: Base64URL.decode(components[2]),
            cipher: Base64URL.decode(components[3]),
            authenticationTag: Base64URL.decode(components[4])
        )
    }
    
    /// Decrypts the `JWE` object and returns the decrypted data.
    /// - Parameters:
    ///   - senderKey: The sender's key, if applicable.
    ///   - recipientKey: The recipient's key, if applicable.
    ///   - sharedKey: A shared key, if applicable.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Returns: The decrypted data as `Data`.
    /// - Throws: Relevant decryption errors.
    public func decrypt(
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> Data {
        guard let alg = getKeyAlgorithm(
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            recipientHeader: nil
        ) else {
            throw JWEError.missingKeyAlgorithm
        }
        
        return try encryptionModule.decryptor(alg: alg).decrypt(
            encodedProtectedHeader: protectedHeaderData,
            encodedUnprotectedHeaderData: unprotectedHeaderData,
            cipher: cipher,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticationData: additionalAuthenticatedData,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey
        )
    }
    
    /// Static method to decrypt a JWE from a compact serialization string.
    /// - Parameters:
    ///   - compactString: The compact serialization string of the JWE.
    ///   - senderKey: The sender's key, if applicable.
    ///   - recipientKey: The recipient's key, if applicable.
    ///   - sharedKey: A shared key, if applicable.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Returns: The decrypted data as `Data`.
    /// - Throws: Relevant decryption errors.
    public static func decrypt(
        compactString: String,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> Data {
        try JWE(compactString: compactString)
            .decrypt(
                senderKey: senderKey,
                recipientKey: recipientKey,
                sharedKey: sharedKey
            )
    }
    
    /// Static method to decrypt a JWE from a JSON representation.
    /// - Parameters:
    ///   - jweJson: The JSON data representing the JWE.
    ///   - senderKey: The sender's key, if applicable.
    ///   - recipientKey: The recipient's key, if applicable.
    ///   - sharedKey: A shared key, if applicable.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Returns: The decrypted data as `Data`.
    /// - Throws: Relevant decryption errors.
    public static func decrypt(
        jweJson: Data,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        tryAllRecipients: Bool = false,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> Data {
        let jsonObj = try JSONDecoder().decode(JWEJson<DefaultJWEHeaderImpl, DefaultJWEHeaderImpl, DefaultJWEHeaderImpl>.self, from: jweJson)
        return try decrypt(
            jweJson: jsonObj,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            tryAllRecipients: tryAllRecipients
        )
    }
    
    // Static method to decrypt a JWE from a JSON representation.
    /// - Parameters:
    ///   - jweJson: The `JWEJson` object representing the JWE.
    ///   - senderKey: The sender's key, if applicable.
    ///   - recipientKey: The recipient's key, if applicable.
    ///   - sharedKey: A shared key, if applicable.
    ///   - encryptionModule: The encryption module to use, defaulting to the standard module.
    /// - Returns: The decrypted data as `Data`.
    /// - Throws: Relevant decryption errors.
    public static func decrypt<
        P: JWERegisteredFieldsHeader, 
        U: JWERegisteredFieldsHeader,
        R: JWERegisteredFieldsHeader
    >(
        jweJson: JWEJson<P, U, R>,
        senderKey: JWK? = nil,
        recipientKey: JWK? = nil,
        sharedKey: JWK? = nil,
        tryAllRecipients: Bool = false,
        encryptionModule: JWEEncryptionModule = JWEEncryptionModule.default
    ) throws -> Data {
        let aad = try AAD.computeAAD(
            header: jweJson.protectedData,
            aad: jweJson.addtionalAuthenticatedData
        )
        
        return try encryptionModule.multiDecryptor.decrypt(
            encodedProtectedHeader: jweJson.protectedData,
            encodedUnprotectedHeaderData: jweJson.sharedProtectedData,
            cipher: jweJson.cipherText,
            recipients: jweJson.recipients.map { ($0.header, $0.encryptedKey)},
            initializationVector: jweJson.initializationVector,
            authenticationTag: jweJson.authenticationTag,
            senderKey: senderKey,
            recipientKey: recipientKey,
            sharedKey: sharedKey,
            additionalAuthenticationData: aad,
            tryAllRecipients: tryAllRecipients
        )
    }
}

extension JWEJson {
    func getRecipient(jwk: JWK) -> Recipient? {
        recipients.first {
            if let thumbprint = try? jwk.thumbprint() {
                if thumbprint == $0.header?.keyID {
                    return true
                }
                
                if
                    let hThumbprint = try? $0.header?.jwk?.thumbprint(),
                    hThumbprint == thumbprint
                {
                    return true
                }
            }
            guard let header = $0.header else { return false }
            
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
    }
}
