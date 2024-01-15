// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

/// A simple implementation of Base64URL decoding and encoding.
/// For more information, see https://www.rfc-editor.org/rfc/rfc4648#section-5.
public enum Base64URL {
    /// Decodes a Base64URL-encoded string to a Data object.
    ///
    /// - Parameter value: The Base64URL-encoded string to be decoded.
    ///
    /// - Throws: `Base64URLError.invalidBase64` if the input string is not a valid Base64URL-encoded string.
    ///           `Base64URLError.unableToCreateDataFromBase64String` if the input string cannot be converted to a Data object.
    public static func decode(_ value: String) throws -> Data {
        var base64 = value
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")

        // Properly pad the string.
        switch base64.count % 4 {
        case 0: break
        case 2: base64 += "=="
        case 3: base64 += "="
        default: throw Base64URL.Error.invalidBase64
        }

        guard let data = Data(base64Encoded: base64) else {
            throw Base64URL.Error.unableToCreateDataFromBase64String(base64)
        }

        return data
    }

    /// Encodes a Data object to a Base64URL-encoded string.
    ///
    /// - Parameter value: The Data object to be encoded.
    public static func encode(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

extension Base64URL {
    /// Enum for handling Base64URLErrors.
    enum Error: Swift.Error {
        /// The input string is not a valid Base64URL-encoded string.
        case invalidBase64
        /// The input string cannot be converted to a Data object.
        case unableToCreateDataFromBase64String(String)
    }
}
