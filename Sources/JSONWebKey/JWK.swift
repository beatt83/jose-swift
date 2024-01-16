// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation

/// A JSON Web Key (JWK) representation [RFC7517](https://www.rfc-editor.org/rfc/rfc7517)
public struct JWK: Equatable, Hashable {
    /// The key type.
    public var keyType: KeyType

    /// The intended use of the public key.
    public var publicKeyUse: PublicKeyUse?

    /// The key operations that the key is intended to be used for.
    public var keyOperations: [KeyOperations]?

    /// The algorithm intended for use with the key.
    public var algorithm: String?

    /// The key value in case of a symmetric key (oct).
    public var key: Data?

    /// The key ID.
    public var keyID: String?

    /// The X.509 URL.
    public var x509URL: String?

    /// The X.509 Certificate Chain.
    public var x509CertificateChain: String?

    /// The X.509 certificate SHA-1 thumbprint.
    public var x509CertificateSHA1Thumbprint: String?

    /// The X.509 certificate SHA-256 thumbprint.
    public var x509CertificateSHA256Thumbprint: String?

    /// The cryptographic curve used with an EC key.
    public var curve: CryptographicCurve?

    /// The value of the "e" parameter for an RSA key.
    public var e: Data?

    /// The value of the "e" parameter for an RSA key.
    public var p: Data?

    /// The value of the "q" parameter for an RSA key.
    public var q: Data?

    /// The value of the "n" parameter for an RSA key.
    public var n: Data?
    
    /// The value of the "dp" parameter for an RSA key.
    public var dp: Data?

    /// The value of the "dq" parameter for an RSA key.
    public var dq: Data?
    
    /// The value of the "qi" parameter for an RSA key.
    public var qi: Data?

    /// The value of the "x" parameter for an EC or OKP key.
    public var x: Data?

    /// The value of the "y" parameter for an EC key.
    public var y: Data?

    /// The value of the "d" parameter for an EC or RSA key.
    public var d: Data?

    // MARK: - Init

    public init(
        keyType: KeyType,
        publicKeyUse: PublicKeyUse? = nil,
        keyOperations: [KeyOperations]? = nil,
        algorithm: String? = nil,
        key: Data? = nil,
        keyID: String? = nil,
        x509URL: String? = nil,
        x509CertificateChain: String? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
        curve: CryptographicCurve? = nil,
        e: Data? = nil,
        p: Data? = nil,
        q: Data? = nil,
        n: Data? = nil,
        dp: Data? = nil,
        dq: Data? = nil,
        qi: Data? = nil,
        x: Data? = nil,
        y: Data? = nil,
        d: Data? = nil
    ) {
        self.keyType = keyType
        self.publicKeyUse = publicKeyUse
        self.keyOperations = keyOperations
        self.algorithm = algorithm
        self.key = key
        self.keyID = keyID
        self.x509URL = x509URL
        self.x509CertificateChain = x509CertificateChain
        self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
        self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
        self.curve = curve
        self.e = e
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.n = n
        self.x = x
        self.y = y
        self.d = d
    }
}

public extension JWK {
    /// The key type.
    ///
    /// For more information, see
    /// - https://www.rfc-editor.org/rfc/rfc7518#section-6.1
    /// - https://www.rfc-editor.org/rfc/rfc8037#section-2
    enum KeyType: String, Codable, Equatable {
        case ellipticCurve = "EC"
        case rsa = "RSA"
        case octetSequence = "oct"
        case octetKeyPair = "OKP"
    }

    /// The intended use of the public key.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7517#section-4.2
    enum PublicKeyUse: String, Codable, Equatable {
        case signature = "sig"
        case encryption = "enc"
    }

    /// The key operations that the key is intended to be used for.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7517#section-4.3
    enum KeyOperations: String, Codable, Equatable {
        case sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits
    }

    /// The cryptographic curves.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7518#section-6.1
    enum CryptographicCurve: String, Codable, CaseIterable, Equatable {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
        case x25519 = "X25519"
        case ed25519 = "Ed25519"
        case x448 = "X448"
        case ed448 = "Ed448"
        case secp256k1
    }
}
