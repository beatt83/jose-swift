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
import JSONWebKey

struct PBE2_SHA256_A128KW: KeyDerivation {
    
    func deriveKey(arguments: [KeyDerivationArguments]) throws -> Data {
        guard
            let password = arguments.password
        else {
            throw CryptoError.missingArguments(["password"])
        }
        guard
            let salt = arguments.saltInput,
            let count = arguments.saltCount
        else {
            throw CryptoError.missingPBS2SaltInputOrCount
        }
        
        return try PBES2SHAKeyDerivation.derive(
            password: password,
            saltInput: salt,
            saltCount: count,
            variant: .sha2(.sha256)
        ).derivedKey
    }
}
