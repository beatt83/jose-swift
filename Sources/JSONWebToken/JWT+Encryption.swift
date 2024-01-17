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
import JSONWebEncryption

extension JWT {
    
    /// Encrypts the payload of a JWT and returns it in JWE format.
    ///
    /// - Parameters:
    ///   - payload: The payload to encrypt, conforming to `JWTRegisteredFieldsClaims`.
    ///   - protectedHeader: A header with fields that will be protected (encrypted).
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted).
    ///   - senderKey: An optional `JWK` representing the sender's key.
    ///   - recipientKey: An optional `JWK` representing the recipient's key.
    ///   - sharedKey: An optional shared symmetric key used in key agreement protocols.
    ///   - cek: An optional content encryption key.
    ///   - initializationVector: An optional initialization vector for the encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload.
    ///   - masterEphemeralKey: A Boolean flag to indicate the use of a master ephemeral key.
    /// - Returns: An instance of `JWT` in JWE format with the encrypted payload.
    /// - Throws: An error if the encryption process fails.
    public static func encrypt<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        payload: C,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK?,
        recipientKey: JWK?,
        sharedKey: JWK?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        masterEphemeralKey: Bool = false
    ) throws -> JWT {
        JWT(
            payload: payload,
            format: .jwe(try JWE(
                payload: JSONEncoder.jose.encode(payload),
                protectedHeader: protectedHeader,
                unprotectedHeader: unprotectedHeader,
                senderKey: senderKey,
                recipientKey: recipientKey,
                cek: cek,
                initializationVector: initializationVector,
                additionalAuthenticationData: additionalAuthenticationData
            ))
        )
    }
    
    /// Encrypts a JWT string as a nested JWT in JWE format.
    ///
    /// - Parameters:
    ///   - jwtString: The JWT string to be encrypted.
    ///   - protectedHeader: A header with fields that will be protected (encrypted).
    ///   - unprotectedHeader: An optional header with fields that will be unprotected (not encrypted).
    ///   - senderKey: An optional `JWK` representing the sender's key.
    ///   - recipientKey: An optional `JWK` representing the recipient's key.
    ///   - sharedKey: An optional shared symmetric key used in key agreement protocols.
    ///   - cek: An optional content encryption key.
    ///   - initializationVector: An optional initialization vector for the encryption algorithm.
    ///   - additionalAuthenticationData: Optional additional data authenticated along with the payload.
    ///   - masterEphemeralKey: A Boolean flag to indicate the use of a master ephemeral key.
    /// - Returns: A string representing the encrypted JWT in JWE format.
    /// - Throws: An error if the encryption process fails.
    public static func encryptAsNested<
        P: JWERegisteredFieldsHeader,
        U: JWERegisteredFieldsHeader
    >(
        jwtString: String,
        protectedHeader: P,
        unprotectedHeader: U? = nil as DefaultJWEHeaderImpl?,
        senderKey: JWK?,
        recipientKey: JWK?,
        sharedKey: JWK?,
        cek: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticationData: Data? = nil,
        masterEphemeralKey: Bool = false
    ) throws -> String {
        var protectedHeader = protectedHeader
        protectedHeader.contentType = "JWT"
        
        return try JWE(
            payload: jwtString.tryToData(),
            protectedHeader: protectedHeader,
            unprotectedHeader: unprotectedHeader,
            senderKey: senderKey,
            recipientKey: recipientKey,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: additionalAuthenticationData
        ).compactSerialization()
    }
}
