// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

/// `ContentEncryptionAlgorithm` is an enumeration representing the supported content encryption algorithms.
public enum ContentEncryptionAlgorithm: String, Codable, Equatable, CaseIterable, Hashable {
    /// AES encryption in CBC mode with an HMAC using SHA-256.
    /// The algorithm uses a 256-bit key and is commonly used for its balance of security and performance.
    case a128CBCHS256 = "A128CBC-HS256"

    /// AES encryption in CBC mode with an HMAC using SHA-384.
    /// This algorithm uses a 384-bit key and provides a higher level of security than A128CBC-HS256.
    case a192CBCHS384 = "A192CBC-HS384"

    /// AES encryption in CBC mode with an HMAC using SHA-512.
    /// It employs a 512-bit key, offering an even higher level of security, suitable for sensitive data protection.
    case a256CBCHS512 = "A256CBC-HS512"

    /// AES encryption using Galois/Counter Mode (GCM) with a 128-bit key.
    /// GCM mode offers both confidentiality and integrity, and is known for its efficiency and performance.
    case a128GCM = "A128GCM"

    /// AES encryption in GCM mode with a 192-bit key.
    /// It offers a higher security level than A128GCM, combining efficiency with stronger encryption.
    case a192GCM = "A192GCM"

    /// AES encryption in GCM mode with a 256-bit key.
    /// This algorithm provides robust security and is widely used in various security protocols and systems.
    case a256GCM = "A256GCM"

    /// Returns the key size in bits used by the encryption algorithm.
    /// - Returns: The size of the key in bits.
    public var keySizeInBits: Int {
        switch self {
        case .a128GCM: return 128
        case .a192GCM: return 192
        case .a256GCM: return 256
        case .a128CBCHS256: return 256
        case .a192CBCHS384: return 384
        case .a256CBCHS512: return 512
        }
    }

    /// Returns the initialization vector size in bits suitable for the encryption algorithm.
    /// - Returns: The size of the initialization vector in bits.
    public var initializationVectorSizeInBits: Int {
        switch self {
        case .a128CBCHS256, .a192CBCHS384, .a256CBCHS512: return 128
        case .a128GCM, .a192GCM, .a256GCM: return 96
        }
    }
    
    /// Provides a `ContentEncryptor` instance based on the selected encryption algorithm.
    /// - Returns: An instance of an encryptor suitable for the algorithm.
    public var encryptor: ContentEncryptor {
        switch self {
        case .a128CBCHS256:
            return AESCBC_SHA256()
        case .a192CBCHS384:
            return AESCBC_SHA384()
        case .a256CBCHS512:
            return AESCBC_SHA512()
        case .a128GCM:
            return AES128GCM()
        case .a192GCM:
            return AES192GCM()
        case .a256GCM:
            return AES256GCM()
        }
    }
    
    /// Provides a `ContentDecryptor` instance based on the selected encryption algorithm.
    /// - Returns: An instance of a decryptor suitable for the algorithm.
    public var decryptor: ContentDecryptor {
        switch self {
        case .a128CBCHS256:
            return AESCBC_SHA256()
        case .a192CBCHS384:
            return AESCBC_SHA384()
        case .a256CBCHS512:
            return AESCBC_SHA512()
        case .a128GCM:
            return AES128GCM()
        case .a192GCM:
            return AES192GCM()
        case .a256GCM:
            return AES256GCM()
        }
    }
}
