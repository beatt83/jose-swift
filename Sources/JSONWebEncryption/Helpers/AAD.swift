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

struct AAD {
    static func computeAAD<H: JWERegisteredFieldsHeader>(header: H?, aad: Data?) throws -> Data {
        guard let header else { return .init() }
        let jsonData = try JSONEncoder.jose.encode(header)
        return try computeAAD(header: jsonData, aad: aad)
    }
    
    static func computeAAD(header: Data?, aad: Data?) throws -> Data {
        if let aad {
            if 
                let aadStr = String(data: aad, encoding: .ascii),
                (try? Base64URL.decode(aadStr)) != nil
            {
                return aad
            }
            guard !isAADAlreadyComposed(aad: aad) else {
                return aad
            }
            let encodedHeader = Base64URL.encode(header ?? .init())
            let encodedAAD = Base64URL.encode(aad)
            let aadResult = [
                encodedHeader,
                encodedAAD
            ].joined(separator: ".").data(using: .ascii) ?? .init()
            return aadResult
        }
        return Base64URL.encode(header ?? .init()).data(using: .ascii) ?? .init()
    }
    
    private static func isAADAlreadyComposed(aad: Data) -> Bool {
        guard
            let str = String(data: aad, encoding: .ascii)
        else {
            return false
        }
        let headerBase64 = str.components(separatedBy: ".")[0]
        guard
            let decodedHeader = try? Base64URL.decode(headerBase64)
        else {
            return false
        }
        return true
    }
    
    static func validateComposedHeader(header: Data?, aad: Data) -> Bool {
        guard
            let header,
            let str = String(data: aad, encoding: .ascii)
        else {
            return false
        }
        let components = str.components(separatedBy: ".")
        guard let base64Header = components.first else {
            return false
        }
        return base64Header == Base64URL.encode(header)
    }
}
