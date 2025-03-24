// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Crypto
import Foundation
import Tools

public extension JWK {
    /// Calculates the JWK thumbprint as per [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
    ///
    /// - Parameters:
    ///   - with: The hash function to use for the JWK thumbprint calculation. Defaults to SHA-256.
    /// - Returns: The Base64URL-encoded JWK thumbprint.
    /// - Throws: `JWK.Error.notSupported` if the JWK type is not supported.
    func thumbprint<H>(
        with _: H = Crypto.SHA256()
    ) throws -> String where H: HashFunction {
        // Get required members of JWK
        // See https://www.rfc-editor.org/rfc/rfc7638#section-3.2
        let requiredMembers: [String: Any]
        switch keyType {
        case .ellipticCurve:
            guard let curve, let x, let y else {
                throw JWK.Error.notSupported
            }
            requiredMembers = [
                "crv": curve.rawValue,
                "kty": keyType.rawValue,
                "x": Base64URL.encode(x),
                "y": Base64URL.encode(y),
            ]
        case .octetKeyPair:
            guard let curve, let x else {
                throw JWK.Error.notSupported
            }
            requiredMembers = [
                "crv": curve.rawValue,
                "kty": keyType.rawValue,
                "x": Base64URL.encode(x),
            ]
        default:
            throw JWK.Error.notSupported
        }

        // Construct JSON object with sorted keys
        let jsonData = try JSONSerialization.data(
            withJSONObject: requiredMembers,
            options: .sortedKeys
        )

        // Hash the JSON data using the specified hash function
        let hashData = H.hash(data: jsonData).withUnsafeBytes { Data($0) }

        // Encode the hash data as a Base64URL string and return it
        return Base64URL.encode(hashData)
    }
}
