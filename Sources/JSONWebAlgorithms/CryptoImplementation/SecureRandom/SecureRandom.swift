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

/// `SecureRandom` provides functionalities to generate cryptographically secure random data.
public struct SecureRandom {

    /// Generates cryptographically secure random data of a specified size.
    ///
    /// This method uses the system's secure random number generator to produce random data, which is suitable for cryptographic operations such as key generation, nonces, or any other use where strong randomness is required.
    ///
    /// - Parameter count: The number of random bytes to generate.
    /// - Returns: A `Data` object containing the generated random bytes.
    /// - Throws: `CryptoError.securityLayerError` if the random number generation fails. This includes an error status code for debugging purposes.
    /// - Note: The function relies on `SecRandomCopyBytes` from Apple's Security framework, ensuring high-quality randomness.
    public static func secureRandomData(count: Int) throws -> Data {

    #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
            var bytes = [Int8](repeating: 0, count: count)
            
            let status = SecRandomCopyBytes(
                kSecRandomDefault,
                count,
                &bytes
            )
            
            if status == errSecSuccess {
                let data = Data(bytes: bytes, count: count)
                return data
            }
            else {
                throw CryptoError.securityLayerError(
                    internalStatus: Int(status),
                    internalError: nil
                )
            }
        
    #else
            return Data((0 ..< count).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) })
    #endif
    }
}
