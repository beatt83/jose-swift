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

extension JWS {
    static func buildSigningData(header: Data, data: Data) throws -> Data {
        if try unencodedBase64Payload(header: header ) {
            let headerB64 = Base64URL.encode(header)
            return try [headerB64, data.tryToString()].joined(separator: ".").tryToData()
        }
        guard let signingData = [header, data]
            .map({ Base64URL.encode($0) })
            .joined(separator: ".")
            .data(using: .utf8)
        else {
            throw JWSError.somethingWentWrong
        }
        return signingData
    }
    
    static func buildJWSString(header: Data, data: Data, signature: Data) throws -> String {
        if try unencodedBase64Payload(header: header) {
            return [header, Data(), signature]
                .map({ Base64URL.encode($0) })
                .joined(separator: ".")
        } else {
            return [header, data, signature]
                .map({ Base64URL.encode($0) })
                .joined(separator: ".")
        }
    }
    
    static func unencodedBase64Payload(header: Data) throws -> Bool {
        let headerFields = try JSONDecoder.jwt.decode(DefaultJWSHeaderImpl.self, from: header)
        guard
            let hasBase64Header = headerFields.base64EncodedUrlPayload,
            !hasBase64Header
        else { return false }
        return true
    }
}
