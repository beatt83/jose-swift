// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

/// Supported JWE cryptographic algorithms for key management.
///
/// For more information, see [RFC7518 Section 4.1](https://www.rfc-editor.org/rfc/rfc7518#section-4.1)
public enum KeyManagementAlgorithm: String, Equatable, Codable {
    /// RSA algorithm with PKCS #1 v1.5 padding.
    case rsa1_5 = "RSA1_5"
    
    /// RSA algorithm with OAEP padding.
    case rsaOAEP = "RSA-OAEP"
    
    /// RSA algorithm with OAEP-256 padding.
    case rsaOAEP256 = "RSA-OAEP-256"
    
    /// AES algorithm with a 128-bit key.
    case a128KW = "A128KW"
    
    /// AES algorithm with a 192-bit key.
    case a192KW = "A192KW"
    
    /// AES algorithm with a 256-bit key.
    case a256KW = "A256KW"
    
    /// Direct use of a shared symmetric key.
    case direct = "dir"
    
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement.
    case ecdhES = "ECDH-ES"
    
    /// ECDH-ES followed by AES key wrap with a 128-bit key.
    case ecdhESA128KW = "ECDH-ES+A128KW"
    
    /// ECDH-ES followed by AES key wrap with a 192-bit key.
    case ecdhESA192KW = "ECDH-ES+A192KW"
    
    /// ECDH-ES followed by AES key wrap with a 256-bit key.
    case ecdhESA256KW = "ECDH-ES+A256KW"
    
    /// AES GCM algorithm with a 128-bit key.
    case a128GCMKW = "A128GCMKW"
    
    /// AES GCM algorithm with a 192-bit key.
    case a192GCMKW = "A192GCMKW"
    
    /// AES GCM algorithm with a 256-bit key.
    case a256GCMKW = "A256GCMKW"
    
    /// PBES2 with HMAC-SHA256 and AES Key Wrap with a 128-bit key.
    case pbes2HS256A128KW = "PBES2-HS256+A128KW"
    
    /// PBES2 with HMAC-SHA384 and AES Key Wrap with a 192-bit key.
    case pbes2HS384A192KW = "PBES2-HS384+A192KW"
    
    /// PBES2 with HMAC-SHA512 and AES Key Wrap with a 256-bit key.
    case pbes2HS512A256KW = "PBES2-HS512+A256KW"
    
    /// Elliptic Curve Diffie-Hellman 1-Party Unilateral key agreement.
    case ecdh1PU = "ECDH-1PU"
    
    /// ECDH-1PU followed by AES key wrap with a 128-bit key.
    case ecdh1PUA128KW = "ECDH-1PU+A128KW"
    
    /// ECDH-1PU followed by AES key wrap with a 192-bit key.
    case ecdh1PUA192KW = "ECDH-1PU+A192KW"
    
    /// ECDH-1PU followed by AES key wrap with a 256-bit key.
    case ecdh1PUA256KW = "ECDH-1PU+A256KW"

    /// Provides a `KeyWrapping` instance suitable for the key management algorithm.
    /// - Returns: An instance conforming to the `KeyWrapping` protocol, or `nil` if wrapping is not supported for the algorithm.
    public var wrapper: KeyWrapping? {
        switch self {
        case .rsa1_5:
            return RSA15KeyWrapper()
        case .rsaOAEP:
            return RSAOAEPKeyWrapper()
        case .rsaOAEP256:
            return RSAOAEP256KeyWrapper()
        case .a128KW:
            return AESKeyWrap()
        case .a192KW:
            return AESKeyWrap()
        case .a256KW:
            return AESKeyWrap()
        case .direct:
            return nil
        case .ecdhES:
            return nil
        case .ecdhESA128KW:
            return AESKeyWrap()
        case .ecdhESA192KW:
            return AESKeyWrap()
        case .ecdhESA256KW:
            return AESKeyWrap()
        case .a128GCMKW:
            return AES128GCM()
        case .a192GCMKW:
            return AES192GCM()
        case .a256GCMKW:
            return AES256GCM()
        case .pbes2HS256A128KW:
            return AESKeyWrap()
        case .pbes2HS384A192KW:
            return AESKeyWrap()
        case .pbes2HS512A256KW:
            return AESKeyWrap()
        case .ecdh1PU:
            return nil
        case .ecdh1PUA128KW:
            return AESKeyWrap()
        case .ecdh1PUA192KW:
            return AESKeyWrap()
        case .ecdh1PUA256KW:
            return AESKeyWrap()
        }
    }
    
    /// Provides a `KeyUnwrapping` instance suitable for the key management algorithm.
    /// - Returns: An instance conforming to the `KeyUnwrapping` protocol, or `nil
    public var unwrapper: KeyUnwrapping? {
        switch self {
        case .rsa1_5:
            return RSA15KeyUnwrap()
        case .rsaOAEP:
            return RSAOAEPKeyUnwrap()
        case .rsaOAEP256:
            return RSAOAEP256KeyUnwrap()
        case .a128KW:
            return AESKeyUnwrap()
        case .a192KW:
            return AESKeyUnwrap()
        case .a256KW:
            return AESKeyUnwrap()
        case .direct:
            return nil
        case .ecdhES:
            return nil
        case .ecdhESA128KW:
            return AESKeyUnwrap()
        case .ecdhESA192KW:
            return AESKeyUnwrap()
        case .ecdhESA256KW:
            return AESKeyUnwrap()
        case .a128GCMKW:
            return AESGCM()
        case .a192GCMKW:
            return AESGCM()
        case .a256GCMKW:
            return AESGCM()
        case .pbes2HS256A128KW:
            return AESKeyUnwrap()
        case .pbes2HS384A192KW:
            return AESKeyUnwrap()
        case .pbes2HS512A256KW:
            return AESKeyUnwrap()
        case .ecdh1PU:
            return nil
        case .ecdh1PUA128KW:
            return AESKeyUnwrap()
        case .ecdh1PUA192KW:
            return AESKeyUnwrap()
        case .ecdh1PUA256KW:
            return AESKeyUnwrap()
        }
    }
    
    public var agreement: KeyAgreementZ? {
        switch self {
        case .ecdhES:
            return ECDHES()
        case .ecdhESA128KW:
            return ECDHES()
        case .ecdhESA192KW:
            return ECDHES()
        case .ecdhESA256KW:
            return ECDHES()
        case .ecdh1PU:
            return ECDH1PU()
        case .ecdh1PUA128KW:
            return ECDH1PU()
        case .ecdh1PUA192KW:
            return ECDH1PU()
        case .ecdh1PUA256KW:
            return ECDH1PU()
        default:
            return nil
        }
    }
    
    /// Provides a `KeyDerivation` instance suitable for the key management algorithm.
    /// - Returns: An instance conforming to the `KeyDerivation` protocol, or `nil
    public var derivation: KeyDerivation? {
        switch self {
        case .pbes2HS256A128KW:
            return PBE2_SHA256_A128KW()
        case .pbes2HS384A192KW:
            return PBE2_SHA384_A192KW()
        case .pbes2HS512A256KW:
            return PBE2_SHA512_A256KW()
        case .ecdhES:
            return ECDHES()
        case .ecdhESA128KW:
            return ECDHES()
        case .ecdhESA192KW:
            return ECDHES()
        case .ecdhESA256KW:
            return ECDHES()
        case .ecdh1PU:
            return ECDH1PU()
        case .ecdh1PUA128KW:
            return ECDH1PU()
        case .ecdh1PUA192KW:
            return ECDH1PU()
        case .ecdh1PUA256KW:
            return ECDH1PU()
        default:
            return nil
        }
    }
}
