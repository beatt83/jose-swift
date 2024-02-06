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
import JSONWebKey

// `JWEParts` represents the constituent parts of a JSON Web Encryption (JWE) object.
/// It's a generic struct that can accommodate different types of headers for both protected and recipient-specific data.
/// - Type parameters:
///   - P: A type conforming to `JWERegisteredFieldsHeader` used for the protected header.
///   - R: A type conforming to `JWERegisteredFieldsHeader` used for the recipient-specific header.
public struct JWEParts<P: JWERegisteredFieldsHeader, R: JWERegisteredFieldsHeader> {
    /// The protected header, containing shared information about the encryption.
    public var protectedHeader: P?

    /// The recipient-specific header, potentially containing information tailored for the individual recipient.
    public var recipientHeader: R?

    /// The ciphertext, which is the encrypted content.
    public let cipherText: Data

    /// The encrypted key, used to decrypt the content.
    public let encryptedKey: Data?

    /// Additional authenticated data, if any, used in the encryption process.
    public let additionalAuthenticationData: Data?

    /// The initialization vector used in the encryption process, for algorithms that require it.
    public let initializationVector: Data?

    /// The authentication tag, verifying the integrity and authenticity of the encrypted content.
    public let authenticationTag: Data?
    
    /// To ensure on cases of multiple encryption the ephemeral key is fully passed
    let ephemeralKey: JWK?
    
    /// Initializes a new `JWEParts` instance with the specified components.
    /// - Parameters:
    ///   - protectedHeader: The protected header of the JWE.
    ///   - recipientHeader: The recipient-specific header of the JWE.
    ///   - cipherText: The encrypted content.
    ///   - encryptedKey: The encrypted key used for decryption.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload.
    ///   - initializationVector: Optional initialization vector for certain encryption algorithms.
    ///   - authenticationTag: Optional authentication tag for verifying integrity and authenticity.
    public init(
        protectedHeader: P?,
        recipientHeader: R?,
        cipherText: Data,
        encryptedKey: Data?,
        additionalAuthenticationData: Data?,
        initializationVector: Data?,
        authenticationTag: Data?
    ) {
        self.init(
            protectedHeader: protectedHeader,
            recipientHeader: recipientHeader,
            cipherText: cipherText,
            encryptedKey: encryptedKey,
            additionalAuthenticationData: additionalAuthenticationData,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            ephemeralKey: nil
        )
    }
    
    init(
        protectedHeader: P?,
        recipientHeader: R?,
        cipherText: Data,
        encryptedKey: Data?,
        additionalAuthenticationData: Data?,
        initializationVector: Data?,
        authenticationTag: Data?,
        ephemeralKey: JWK?
    ) {
        self.protectedHeader = protectedHeader
        self.recipientHeader = recipientHeader
        self.encryptedKey = encryptedKey
        self.additionalAuthenticationData = additionalAuthenticationData
        self.initializationVector = initializationVector
        self.cipherText = cipherText
        self.authenticationTag = authenticationTag
        self.ephemeralKey = ephemeralKey
    }
}
