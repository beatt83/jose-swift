// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation
import Tools

extension JWK: Codable {
    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case publicKeyUse = "use"
        case keyOperations = "keyOps"
        case algorithm = "alg"
        case key = "k"
        case keyID = "kid"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
        case curve = "crv"
        case e, p, q, n, x, y, d
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(keyType, forKey: .keyType)
        try container.encodeIfPresent(publicKeyUse, forKey: .publicKeyUse)
        try container.encodeIfPresent(keyOperations, forKey: .keyOperations)
        try container.encodeIfPresent(algorithm, forKey: .algorithm)
        if let value = key {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .key)
        }
        try container.encodeIfPresent(keyID, forKey: .keyID)
        try container.encodeIfPresent(x509URL, forKey: .x509URL)
        try container.encodeIfPresent(x509CertificateChain, forKey: .x509CertificateChain)
        try container.encodeIfPresent(x509CertificateSHA1Thumbprint, forKey: .x509CertificateSHA1Thumbprint)
        try container.encodeIfPresent(x509CertificateSHA256Thumbprint, forKey: .x509CertificateSHA256Thumbprint)
        try container.encodeIfPresent(curve, forKey: .curve)
        if let value = e {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .e)
        }
        if let value = p {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .p)
        }
        if let value = q {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .q)
        }
        if let value = n {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .n)
        }
        if let value = x {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .x)
        }
        if let value = y {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .y)
        }
        if let value = d {
            try container.encodeIfPresent(Base64URL.encode(value), forKey: .d)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyType = try container.decode(JWK.KeyType.self, forKey: .keyType)
        publicKeyUse = try container.decodeIfPresent(JWK.PublicKeyUse.self, forKey: .publicKeyUse)
        keyOperations = try container.decodeIfPresent([JWK.KeyOperations].self, forKey: .keyOperations)
        algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm)
        if let value = try container.decodeIfPresent(String.self, forKey: .key) {
            key = try Base64URL.decode(value)
        }
        keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
        x509URL = try container.decodeIfPresent(String.self, forKey: .x509URL)
        x509CertificateChain = try container.decodeIfPresent([String].self, forKey: .x509CertificateChain)
        x509CertificateSHA1Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA1Thumbprint)
        x509CertificateSHA256Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA256Thumbprint)
        curve = try container.decodeIfPresent(JWK.CryptographicCurve.self, forKey: .curve)
        if let value = try container.decodeIfPresent(String.self, forKey: .e) {
            e = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .p) {
            p = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .q) {
            q = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .n) {
            n = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .x) {
            x = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .y) {
            y = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .d) {
            d = try Base64URL.decode(value)
        }
    }
}
