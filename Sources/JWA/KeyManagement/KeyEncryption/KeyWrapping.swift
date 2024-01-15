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
import JWK

/// `KeyEncryptionArguments` is an enumeration defining additional arguments that can be used in key encryption processes.
public enum KeyEncryptionArguments {
    /// Data specific to one party involved in the key agreement (usually the initiator).
    case agreementPartyUInfo(Data)

    /// Data specific to the other party involved in the key agreement (usually the responder).
    case agreementPartyVInfo(Data)

    /// The initialization vector used in certain encryption algorithms to provide additional randomness.
    case initializationVector(Data)

    /// The authentication tag used to verify the integrity and authenticity of a message in authenticated encryption.
    case authenticationTag(Data)

    /// PBES2 salt input used in key derivation functions.
    case pbs2saltInput(Data)

    /// The iteration count for the PBES2 salt input in key derivation functions.
    case pbs2saltCount(Int)

    /// Allows for custom data to be included, identified by a key.
    case customData(key: String, value: Data)

    /// Allows for a custom JSON Web Key (JWK) to be included, identified by a key.
    case customJWK(key: String, value: JWK)
}

/// `KeyEncriptionResultMetadata` is a struct representing the metadata of a key encryption result.
public struct KeyEncriptionResultMetadata {
    /// The encrypted content encryption key (CEK).
    public let encryptedKey: Data

    /// Optional initialization vector associated with the key encryption.
    public let initializationVector: Data?

    /// Optional authentication tag for verifying the integrity and authenticity of the encrypted key.
    public let authenticationTag: Data?

    /// Optional PBES2 salt input used in the encryption process.
    public let pbs2saltInput: Data?

    /// Optional iteration count for the PBES2 salt input.
    public let pbs2saltCount: Int?

    /// Additional metadata that may be included in the encryption process.
    public let otherMetadata: [String: Data]

    /// Initializes a new `KeyEncriptionResultMetadata` instance with the specified encryption result and metadata.
    public init(
        encryptedKey: Data,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        pbs2saltInput: Data? = nil,
        pbs2saltCount: Int? = nil,
        otherMetadata: [String: Data] = [:]
    ) {
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.authenticationTag = authenticationTag
        self.pbs2saltInput = pbs2saltInput
        self.pbs2saltCount = pbs2saltCount
        self.otherMetadata = otherMetadata
    }
}

/// `KeyWrapping` is a protocol defining functionality for encrypting (wrapping) a content encryption key (CEK).
public protocol KeyWrapping {
    /// Encrypts (wraps) a content encryption key using a specified JSON Web Key (JWK) and additional arguments.
    /// - Parameters:
    ///   - cek: The content encryption key to be encrypted (wrapped).
    ///   - using: The `JWK` used for the encryption process.
    ///   - arguments: An array of `KeyEncryptionArguments` providing additional information required for encryption.
    /// - Returns: A `KeyEncriptionResultMetadata` containing the encrypted key and associated metadata.
    /// - Throws: An error if key wrapping fails. This could be due to incorrect keys, incompatible arguments, or other cryptographic issues.
    func contentKeyEncrypt(
        cek: Data,
        using: JWK,
        arguments: [KeyEncryptionArguments]
    ) throws -> KeyEncriptionResultMetadata
}


extension Array where Element == KeyEncryptionArguments {
    var agreementPartyUInfo: Data? {
        return self.compactMap {
            if case .agreementPartyUInfo(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var agreementPartyVInfo: Data? {
        return self.compactMap {
            if case .agreementPartyVInfo(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var initializationVector: Data? {
        return self.compactMap {
            if case .initializationVector(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var authenticationTag: Data? {
        return self.compactMap {
            if case .authenticationTag(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var pbs2saltInput: Data? {
        return self.compactMap {
            if case .pbs2saltInput(let data) = $0 {
                return data
            }
            return nil
        }.first
    }

    var pbs2saltCount: Int? {
        return self.compactMap {
            if case .pbs2saltCount(let data) = $0 {
                return data
            }
            return nil
        }.first
    }
}

extension KeyEncryptionArguments {
    var agreementPartyUInfo: Data? {
        if case .agreementPartyUInfo(let data) = self {
            return data
        }
        return nil
    }

    var agreementPartyVInfo: Data? {
        if case .agreementPartyUInfo(let data) = self {
            return data
        }
        return nil
    }

    var initializationVector: Data? {
        if case .initializationVector(let data) = self {
            return data
        }
        return nil
    }

    var authenticationTag: Data? {
        if case .authenticationTag(let data) = self {
            return data
        }
        return nil
    }

    var pbs2saltInput: Data? {
        if case .pbs2saltInput(let data) = self {
            return data
        }
        return nil
    }

    var pbs2saltCount: Int? {
        if case .pbs2saltCount(let data) = self {
            return data
        }
        return nil
    }
}
