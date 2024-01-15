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
import JWA

extension KeyManagementAlgorithm {
    /// `Family` is an enumeration representing different families of cryptographic algorithms.
    public enum Family: String, CaseIterable {
        /// RSA family of algorithms.
        case rsa = "RSA"

        /// AES (Advanced Encryption Standard) family of algorithms.
        case aes = "AES"

        /// ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) family of algorithms.
        case ecdhes = "ECDH-ES"

        /// ECDH-1PU family of algorithms, a variant of ECDH used in some key agreement protocols.
        case ecdh1pu = "ECDH-1PU"

        /// PBES2 (Password-Based Encryption Scheme 2) family of algorithms.
        case pbes2 = "PBES2"

        /// Direct use of a shared symmetric key.
        case direct = "DIRECT"
    }

    /// Property to determine the family of the cryptographic algorithm.
    /// Based on the algorithm used, it categorizes into one of the defined families.
    public var family: Family {
        switch self {
        case .rsa1_5, .rsaOAEP, .rsaOAEP256:
            return .rsa
        case .a128KW, .a192KW, .a256KW, .a128GCMKW, .a192GCMKW, .a256GCMKW:
            return .aes
        case .direct:
            return .direct
        case .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW:
            return .ecdhes
        case .pbes2HS256A128KW, .pbes2HS384A192KW, .pbes2HS512A256KW:
            return .pbes2
        case .ecdh1PU, .ecdh1PUA128KW, .ecdh1PUA192KW, .ecdh1PUA256KW:
            return .ecdh1pu
        }
    }
}
