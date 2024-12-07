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
import Tools

/// `JWE` struct represents a JSON Web Encryption (JWE) structure as defined in [RFC7516](https://tools.ietf.org/html/rfc7516).
/// It provides mechanisms to encrypt content, represented as the `cipher`, along with various headers and authentication data.
public struct JWE: Sendable {
    /// The `protectedHeader` is a JWE header with registered fields that are integrity protected.
    public let protectedHeader: JWERegisteredFieldsHeader

    /// `protectedHeaderData` represents the raw binary data of the protected header.
    public  let protectedHeaderData: Data

    /// The `cipher` contains the encrypted payload.
    public let cipher: Data

    /// `unprotectedHeader` is an optional JWE header with registered fields that are not integrity protected.
    public let unprotectedHeader: JWERegisteredFieldsHeader?

    /// `unprotectedHeaderData` represents the raw binary data of the shared unprotected header, if available.
    public let unprotectedHeaderData: Data?

    /// `encryptedKey` is an optional field containing the encrypted key used to encrypt the payload.
    public let encryptedKey: Data?

    /// `initializationVector` is an optional field used in certain encryption algorithms to provide additional randomness.
    public let initializationVector: Data?

    /// `authenticationTag` is an optional field used to store integrity information about the payload and headers.
    public let authenticationTag: Data?

    /// `additionalAuthenticatedData` is optional extra data that can be authenticated along with the payload but is not encrypted.
    public let additionalAuthenticatedData: Data?
    
    /// Generates a compact serialization of the `JWE` object.
    /// This serialization is a string representation consisting of base64url-encoded values separated by periods.
    /// - Returns: A compact serialized string representation of the JWE object.
    public var compactSerialization: String {
        return [
            Base64URL.encode(protectedHeaderData),
            Base64URL.encode(encryptedKey ?? .init()),
            Base64URL.encode(initializationVector ?? .init()),
            Base64URL.encode(cipher),
            Base64URL.encode(authenticationTag ?? .init())
        ].joined(separator: ".")
    }
    
    /// Initializes a new `JWE` object with the specified parameters.
    /// - Parameters:
    ///   - protectedHeader: The protected header with registered fields.
    ///   - protectedHeaderData: The raw data of the protected header.
    ///   - cipher: The encrypted content.
    ///   - unprotectedHeader: Optional shared unprotected header.
    ///   - unprotectedHeaderData: Optional raw data of the shared unprotected header.
    ///   - encryptedKey: Optional encrypted key.
    ///   - initializationVector: Optional initialization vector.
    ///   - authenticationTag: Optional authentication tag.
    ///   - additionalAuthenticatedData: Optional additional authenticated data.
    public init(
        protectedHeader: JWERegisteredFieldsHeader,
        protectedHeaderData: Data,
        cipher: Data,
        unprotectedHeader: JWERegisteredFieldsHeader? = nil,
        unprotectedHeaderData: Data? = nil,
        encryptedKey: Data? = nil,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        additionalAuthenticatedData: Data? = nil
    ) {
        self.protectedHeader = protectedHeader
        self.protectedHeaderData = protectedHeaderData
        self.unprotectedHeader = unprotectedHeader
        self.unprotectedHeaderData = unprotectedHeaderData
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.cipher = cipher
        self.authenticationTag = authenticationTag
        self.additionalAuthenticatedData = additionalAuthenticatedData
    }
    
    /// Initializes a new `JWE` object by decoding the protected header from the provided data and setting other parameters.
    /// Throws an error if the protected header cannot be decoded.
    /// - Parameters:
    ///   - protectedHeader: The raw data of the protected header.
    ///   - encryptedKey: The encrypted key.
    ///   - initializationVector: The initialization vector.
    ///   - cipher: The encrypted content.
    ///   - authenticationTag: The authentication tag.
    public init(
        protectedHeader: Data,
        encryptedKey: Data,
        initializationVector: Data,
        cipher: Data,
        authenticationTag: Data
    ) throws {
        self.init(
            protectedHeader: try JSONDecoder().decode(DefaultJWEHeaderImpl.self, from: protectedHeader),
            protectedHeaderData: protectedHeader,
            cipher: cipher,
            unprotectedHeader: nil,
            unprotectedHeaderData: nil,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            authenticationTag: authenticationTag,
            additionalAuthenticatedData: nil
        )
    }
}
