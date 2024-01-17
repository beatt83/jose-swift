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

/// `SigningAlgorithm` represents the various supported algorithms for signing in a JSON Web Signature (JWS).
/// Each case of this enum represents a different cryptographic algorithm used for digital signatures or message authentication codes (MACs).
/// - `HS256`, `HS384`, `HS512`: HMAC (Hash-based Message Authentication Code) using SHA-256, SHA-384, and SHA-512 hash functions, respectively.
/// - `RS256`, `RS384`, `RS512`: RSASSA-PKCS1-v1_5 signature algorithm using SHA-256, SHA-384, and SHA-512 hash functions, respectively.
/// - `ES256`, `ES384`, `ES512`: ECDSA (Elliptic Curve Digital Signature Algorithm) using P-256, P-384, and P-521 curves along with SHA-256, SHA-384, and SHA-512 hash functions, respectively.
/// - `ES256K`: ECDSA using the secp256k1 curve and SHA-256 hash function.
/// - `PS256`, `PS384`, `PS512`: RSASSA-PSS (RSA Probabilistic Signature Scheme) using SHA-256, SHA-384, and SHA-512 hash functions, respectively, and MGF1 (Mask Generation Function 1).
/// - `none`: Represents the absence of a digital signature or MAC.
/// - `invalid`: A placeholder for an invalid or unsupported algorithm, useful for error handling or invalid state representation.
public enum SigningAlgorithm: String, Codable {
    /// HMAC using SHA-256
    case HS256 = "HS256"
    
    /// HMAC using SHA-384
    case HS384 = "HS384"
    
    /// HMAC using SHA-512
    case HS512 = "HS512"
    
    /// RSASSA-PKCS1-v1_5 using SHA-256
    case RS256 = "RS256"
    
    /// RSASSA-PKCS1-v1_5 using SHA-384
    case RS384 = "RS384"
    
    /// RSASSA-PKCS1-v1_5 using SHA-512
    case RS512 = "RS512"
    
    /// ECDSA using P-256 and SHA-256
    case ES256 = "ES256"
    
    /// ECDSA using P-384 and SHA-384
    case ES384 = "ES384"
    
    /// ECDSA using P-521 and SHA-512
    case ES512 = "ES512"
    
    /// ECDSA using secp256k1 and SHA-256
    case ES256K = "ES256K"
    
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    case PS256 = "PS256"
    
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    case PS384 = "PS384"
    
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    case PS512 = "PS512"
    
    /// EdDSA using Ed25519
    case EdDSA = "EdDSA"
    
    /// No digital signature or MAC performed
    case none = "none"
    
    /// Invalid algorithm that will always fail
    case invalid = "invalid"
    
    public var cryptoSigner: Signer? {
        switch self {
        case .HS256:
            return AvailableCrypto.HMAC_SHA256.signer
        case .HS384:
            return AvailableCrypto.HMAC_SHA384.signer
        case .HS512:
            return AvailableCrypto.HMAC_SHA512.signer
        case .RS256:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA256.signer
        case .RS384:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA384.signer
        case .RS512:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA512.signer
        case .ES256:
            return AvailableCrypto.P256_ECDSA_WithSHA256.signer
        case .ES384:
            return AvailableCrypto.P384_ECDSA_WithSHA384.signer
        case .ES512:
            return AvailableCrypto.P521_ECDSA_WithSHA512.signer
        case .ES256K:
            return AvailableCrypto.SECP256K1_ECDSA_WithSHA256.signer
        case .PS256:
            return AvailableCrypto.RSASSA_PSS_WithSHA256_MGF1_WithSHA256.signer
        case .PS384:
            return AvailableCrypto.RSASSA_PSS_WithSHA384_MGF1_WithSHA384.signer
        case .PS512:
            return AvailableCrypto.RSASSA_PSS_WithSHA512_MGF1_WithSHA512.signer
        case .EdDSA:
            return AvailableCrypto.EdDSA.signer
        case .none:
            return nil
        case .invalid:
            return nil
        }
    }
    
    public var cryptoVerifier: Verifier? {
        switch self {
        case .HS256:
            return AvailableCrypto.HMAC_SHA256.verifier
        case .HS384:
            return AvailableCrypto.HMAC_SHA384.verifier
        case .HS512:
            return AvailableCrypto.HMAC_SHA512.verifier
        case .RS256:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA256.verifier
        case .RS384:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA384.verifier
        case .RS512:
            return AvailableCrypto.RSASSA_PKCS1_V1_5_WithSHA512.verifier
        case .ES256:
            return AvailableCrypto.P256_ECDSA_WithSHA256.verifier
        case .ES384:
            return AvailableCrypto.P384_ECDSA_WithSHA384.verifier
        case .ES512:
            return AvailableCrypto.P521_ECDSA_WithSHA512.verifier
        case .ES256K:
            return AvailableCrypto.SECP256K1_ECDSA_WithSHA256.verifier
        case .PS256:
            return AvailableCrypto.RSASSA_PSS_WithSHA256_MGF1_WithSHA256.verifier
        case .PS384:
            return AvailableCrypto.RSASSA_PSS_WithSHA384_MGF1_WithSHA384.verifier
        case .PS512:
            return AvailableCrypto.RSASSA_PSS_WithSHA512_MGF1_WithSHA512.verifier
        case .EdDSA:
            return AvailableCrypto.EdDSA.verifier
        case .none:
            return nil
        case .invalid:
            return nil
        }
    }
}
