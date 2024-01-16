// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation
@_implementationOnly import OpenSSL

/// The Curve448 Elliptic Curve.
public enum Curve448 {
    static let keySize = 56
}

extension Curve448 {
    public enum KeyAgreement {
        public struct PublicKey {
            let x: Data

            /// Initializes a Curve448 Key for Key Agreement.
            ///
            /// - Parameter rawRepresentation: The data representation of the key
            /// - Returns: An initialized key if the data is valid.
            /// - Throws: Throws if the data is not a valid key.
            public init(rawRepresentation: some ContiguousBytes) throws {
                x = rawRepresentation.withUnsafeBytes { Data($0) }
                var keyData = [UInt8](x)
                let pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nil, &keyData, Curve448.keySize)
                defer { EVP_PKEY_free(pkey) }
                if pkey == nil {
                    throw CryptoKitError.underlyingCoreCryptoError(error: -1)
                }
            }

            /// A data representation of the public key
            public var rawRepresentation: Data {
                x
            }
        }

        public struct PrivateKey {
            let d: Data

            /// Generates a new X448 private key.
            public init() {
                var pkey: OpaquePointer?
                let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nil)
                defer { EVP_PKEY_CTX_free(ctx) }
                EVP_PKEY_keygen_init(ctx)
                EVP_PKEY_keygen(ctx, &pkey)
                var keyLength = 0
                EVP_PKEY_get_raw_private_key(pkey, nil, &keyLength)
                var keyData = [UInt8](repeating: 0, count: keyLength)
                EVP_PKEY_get_raw_private_key(pkey, &keyData, &keyLength)
                d = Data(keyData)
                EVP_PKEY_free(pkey)
            }

            /// Initializes the key with data.
            ///
            /// - Parameter data: The 56-bytes representation of the private key.
            public init(rawRepresentation: some ContiguousBytes) throws {
                d = rawRepresentation.withUnsafeBytes { Data($0) }
                var keyData = [UInt8](d)
                let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, nil, &keyData, Curve448.keySize)
                defer { EVP_PKEY_free(pkey) }
                if pkey == nil {
                    throw CryptoKitError.underlyingCoreCryptoError(error: -1)
                }
            }

            /// Returns the associated X448 public key.
            ///
            /// - Returns: The public key
            public var publicKey: Curve448.KeyAgreement.PublicKey {
                var keyData = [UInt8](d)
                let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, nil, &keyData, Curve448.keySize)
                defer { EVP_PKEY_free(pkey) }
                var keyLength = 0
                EVP_PKEY_get_raw_public_key(pkey, nil, &keyLength)
                var publicKeyData = [UInt8](repeating: 0, count: keyLength)
                EVP_PKEY_get_raw_public_key(pkey, &publicKeyData, &keyLength)
                return (try? Curve448.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)).unsafelyUnwrapped
            }

            /// Performs an elliptic curve Diffie-Hellmann key agreement over X448.
            ///
            /// - Parameter publicKeyShare: The public key share to perform the key agreement with.
            /// - Returns: The shared secret
            /// - Throws: Throws if the operation failed to be performed.
            public func sharedSecretFromKeyAgreement(with publicKeyShare: Curve448.KeyAgreement.PublicKey) throws -> Data {
                var sharedSecretKeyLength = 0
                var keyData = [UInt8](d)
                let pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, nil, &keyData, Curve448.keySize)
                var peerKeyData = [UInt8](publicKeyShare.x)
                let peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nil, &peerKeyData, Curve448.keySize)
                let ctx = EVP_PKEY_CTX_new(pkey, nil)
                defer {
                    EVP_PKEY_free(pkey)
                    EVP_PKEY_free(peerKey)
                    EVP_PKEY_CTX_free(ctx)
                }
                if ctx == nil {
                    throw CryptoKitError.incorrectKeySize
                }
                let result_EVP_PKEY_derive_init = EVP_PKEY_derive_init(ctx)
                if result_EVP_PKEY_derive_init <= 0 {
                    throw CryptoKitError.underlyingCoreCryptoError(error: result_EVP_PKEY_derive_init)
                }
                let result_EVP_PKEY_derive_set_peer = EVP_PKEY_derive_set_peer(ctx, peerKey)
                if result_EVP_PKEY_derive_set_peer <= 0 {
                    throw CryptoKitError.underlyingCoreCryptoError(error: result_EVP_PKEY_derive_set_peer)
                }
                let result1_EVP_PKEY_derive = EVP_PKEY_derive(ctx, nil, &sharedSecretKeyLength)
                if result1_EVP_PKEY_derive <= 0 {
                    throw CryptoKitError.underlyingCoreCryptoError(error: result1_EVP_PKEY_derive)
                }
                var sharedSecretKey = [UInt8](repeating: 0, count: sharedSecretKeyLength)
                let result2_EVP_PKEY_derive = EVP_PKEY_derive(ctx, &sharedSecretKey, &sharedSecretKeyLength)
                if result2_EVP_PKEY_derive <= 0 {
                    throw CryptoKitError.underlyingCoreCryptoError(error: result2_EVP_PKEY_derive)
                }
                return Data(sharedSecretKey)
            }

            /// A data representation of the private key
            public var rawRepresentation: Data {
                d
            }
        }
    }
}
