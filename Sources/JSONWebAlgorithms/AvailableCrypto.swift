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

public enum AvailableCrypto {
    case HMAC_SHA256
    case HMAC_SHA384
    case HMAC_SHA512
    case RSASSA_PKCS1_V1_5_WithSHA256
    case RSASSA_PKCS1_V1_5_WithSHA384
    case RSASSA_PKCS1_V1_5_WithSHA512
    case P256_ECDSA_WithSHA256
    case P384_ECDSA_WithSHA384
    case P521_ECDSA_WithSHA512
    case SECP256K1_ECDSA_WithSHA256
    case RSASSA_PSS_WithSHA256_MGF1_WithSHA256
    case RSASSA_PSS_WithSHA384_MGF1_WithSHA384
    case RSASSA_PSS_WithSHA512_MGF1_WithSHA512
    
    public var algorithm: String {
        switch self {
        case .HMAC_SHA256:
            return "HS256"
        case .HMAC_SHA384:
            return "HS384"
        case .HMAC_SHA512:
            return "HS512"
        case .RSASSA_PKCS1_V1_5_WithSHA256:
            return "RS256"
        case .RSASSA_PKCS1_V1_5_WithSHA384:
            return "RS384"
        case .RSASSA_PKCS1_V1_5_WithSHA512:
            return "RS512"
        case .RSASSA_PSS_WithSHA256_MGF1_WithSHA256:
            return "PS256"
        case .RSASSA_PSS_WithSHA384_MGF1_WithSHA384:
            return "PS384"
        case .RSASSA_PSS_WithSHA512_MGF1_WithSHA512:
            return "PS512"
        case .P256_ECDSA_WithSHA256:
            return "ES256"
        case .P384_ECDSA_WithSHA384:
            return "ES384"
        case .P521_ECDSA_WithSHA512:
            return "ES512"
        case .SECP256K1_ECDSA_WithSHA256:
            return "ES256K"
        }
    }
    
    public var curve: String? {
        switch self {
        case .P256_ECDSA_WithSHA256:
            return "P-256"
        case .P384_ECDSA_WithSHA384:
            return "P-384"
        case .P521_ECDSA_WithSHA512:
            return "P-521"
        case .SECP256K1_ECDSA_WithSHA256:
            return "secp256k1"
        default:
            return nil
        }
    }
    
    public var algorithmDescription: String {
        switch self {
        case .HMAC_SHA256:
            return "HMAC with SHA256"
        case .HMAC_SHA384:
            return "HMAC with SHA384"
        case .HMAC_SHA512:
            return "HMAC with SHA512"
        case .RSASSA_PKCS1_V1_5_WithSHA256:
            return "RSASSA-PKCS1-v1_5 with SHA256"
        case .RSASSA_PKCS1_V1_5_WithSHA384:
            return "RSASSA-PKCS1-v1_5 with SHA384"
        case .RSASSA_PKCS1_V1_5_WithSHA512:
            return "RSASSA-PKCS1-v1_5 with SHA512"
        case .P256_ECDSA_WithSHA256:
            return "ECDSA using P-256 and SHA256"
        case .P384_ECDSA_WithSHA384:
            return "ECDSA using P-384 and SHA-384"
        case .P521_ECDSA_WithSHA512:
            return "ECDSA using P-521 and SHA-512"
        case .SECP256K1_ECDSA_WithSHA256:
            return "ECDSA using secp256k1 curve and SHA-256"
        case .RSASSA_PSS_WithSHA256_MGF1_WithSHA256:
            return "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"
        case .RSASSA_PSS_WithSHA384_MGF1_WithSHA384:
            return "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"
        case .RSASSA_PSS_WithSHA512_MGF1_WithSHA512:
            return "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"
        }
    }
    
    public var signer: Signer {
        switch self {
        case .HMAC_SHA256:
            return HS256Signer()
        case .HMAC_SHA384:
            return HS384Signer()
        case .HMAC_SHA512:
            return HS512Signer()
        case .RSASSA_PKCS1_V1_5_WithSHA256:
            return RS256Signer()
        case .RSASSA_PKCS1_V1_5_WithSHA384:
            return RS384Signer()
        case .RSASSA_PKCS1_V1_5_WithSHA512:
            return RS512Signer()
        case .P256_ECDSA_WithSHA256:
            return ES256Signer()
        case .P384_ECDSA_WithSHA384:
            return ES384Signer()
        case .P521_ECDSA_WithSHA512:
            return ES512Signer()
        case .SECP256K1_ECDSA_WithSHA256:
            return ES256KSigner()
        case .RSASSA_PSS_WithSHA256_MGF1_WithSHA256:
            return PS256Signer()
        case .RSASSA_PSS_WithSHA384_MGF1_WithSHA384:
            return PS384Signer()
        case .RSASSA_PSS_WithSHA512_MGF1_WithSHA512:
            return PS512Signer()
        }
    }
    
    public var verifier: Verifier {
        switch self {
        case .HMAC_SHA256:
            return HS256Verifier()
        case .HMAC_SHA384:
            return HS384Verifier()
        case .HMAC_SHA512:
            return HS512Verifier()
        case .RSASSA_PKCS1_V1_5_WithSHA256:
            return RS256Verifier()
        case .RSASSA_PKCS1_V1_5_WithSHA384:
            return RS384Verifier()
        case .RSASSA_PKCS1_V1_5_WithSHA512:
            return RS512Verifier()
        case .P256_ECDSA_WithSHA256:
            return ES256Verifier()
        case .P384_ECDSA_WithSHA384:
            return ES384Verifier()
        case .P521_ECDSA_WithSHA512:
            return ES521Verifier()
        case .SECP256K1_ECDSA_WithSHA256:
            return ES256KVerifier()
        case .RSASSA_PSS_WithSHA256_MGF1_WithSHA256:
            return PS256Verifier()
        case .RSASSA_PSS_WithSHA384_MGF1_WithSHA384:
            return PS384Verifier()
        case .RSASSA_PSS_WithSHA512_MGF1_WithSHA512:
            return PS512Verifier()
        }
    }
}
