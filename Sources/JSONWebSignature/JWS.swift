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

/// `JWS` represents a JSON Web Signature (JWS) structure as defined in [RFC7515](https://tools.ietf.org/html/rfc7515).
/// It encapsulates the protected header, payload, and signature of a JWS,
/// and provides functionality for initializing and manipulating JWS objects in compliance with the standard.
public struct JWS {
    /// The protected header fields of the JWS as specified in RFC 7515.
    /// This header contains metadata about the type of signature and algorithm used.
    public let protectedHeader: JWSRegisteredFieldsHeader
    
    /// The payload data that is signed or encrypted, conforming to RFC 7515 specifications.
    public let data: Data
    
    /// The signature of the JWS
    /// It is computed based on the protected header and the payload data.
    public let signature: Data
    
    /// The compact serialization of the JWS as a string, following the format outlined in RFC 7515.
    /// This string is a Base64URL encoded representation of the header, payload, and signature.
    public let compactSerilization: String
    
    /// The raw header data, as used in the JWS structure.
    public let header: Data
    
    /// Initializes a new JWS object using raw header data, payload data, and signature,
    /// as per the structure and encoding rules.
    /// Throws an error if the header data cannot be decoded into a `JWSProtectedFieldsHeader`.
    ///
    /// - Parameters:
    ///   - header: The raw header data.
    ///   - data: The payload data.
    ///   - signature: The signature data.
    public init(header: Data, data: Data, signature: Data) throws {
        self.header = header
        self.protectedHeader = try JSONDecoder().decode(DefaultJWSHeaderImpl.self, from: header)
        self.data = data
        self.signature = signature
        self.compactSerilization = try JWS.buildJWSString(header: header, data: data, signature: signature)
    }
    
    /// Initializes a new JWS object using a `JWSProtectedFieldsHeader` instance, payload data, and signature,
    /// encoding the header.
    ///
    /// - Parameters:
    ///   - header: The `JWSProtectedFieldsHeader` instance.
    ///   - data: The payload data.
    ///   - signature: The signature data.
    public init(header: JWSRegisteredFieldsHeader, data: Data, signature: Data) throws {
        let headerData = try JSONEncoder().encode(header)
        self.header = headerData
        self.protectedHeader = header
        self.data = data
        self.signature = signature
        self.compactSerilization = try JWS.buildJWSString(header: headerData, data: data, signature: signature)
    }
    
    /// Initializes a new JWS object from a compact serialization string.
    /// Decodes the header, payload, and signature from the string.
    /// Throws an error if the string format is invalid or decoding fails.
    ///
    /// - Parameters:
    ///   - jwsString: The compact serialization string of the JWS.
    ///   - headerType: The type of the header to decode into.
    public init(jwsString: String, headerType: JWSRegisteredFieldsHeader.Type) throws {
        let components = jwsString.components(separatedBy: ".")
        guard components.count == 3 else {
            throw JWSError.invalidString
        }
        let headerDecoded = try Base64URL.decode(components[0])
        self.data = try Base64URL.decode(components[1])
        self.signature = try Base64URL.decode(components[2])
        self.header = headerDecoded
        self.protectedHeader = try JSONDecoder().decode(headerType, from: headerDecoded)
        self.compactSerilization = jwsString
    }
    
    /// Initializes a new JWS object from a compact serialization string using a default header type,
    /// following the format and decoding rules specified in RFC 7515.
    ///
    /// - Parameter jwsString: The compact serialization string of the JWS.
    public init(jwsString: String) throws {
        try self.init(jwsString: jwsString, headerType: DefaultJWSHeaderImpl.self)
    }
}
