// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation

/// A protocol representing a hash function that has a maximum input length.
public protocol HashFunctionMaxInputLength {
    static var maxInputLength: UInt64 { get }
}

extension SHA256: HashFunctionMaxInputLength {
    public static var maxInputLength: UInt64 { UInt64.max - 1 }
}

/// An enumeration that represents the possible errors that can occur during the Concat KDF key derivation.
public enum ConcatKDFError: Error {
    case invalidInput
}

/// The Concat Key Derivation Function (KDF), as defined in Section 5.8.1 of [NIST.800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
public struct ConcatKDF<H> where H: HashFunction, H: HashFunctionMaxInputLength {
    /// Derives a symmetric key using the Concat KDF algorithm.
    ///
    /// - Parameters:
    ///     - z: A byte string representing the shared secret z.
    ///     - keyDataLen: The length (in bits) of the secret keying material to be derived.
    ///     - algorithmID: An identifier for the algorithm used.
    ///     - partyUInfo: Additional data supplied by the party generating the key.
    ///     - partyVInfo: Additional data supplied by the party receiving the key.
    ///     - suppPubInfo: Public data supplied by the party generating the key.
    ///     - suppPrivInfo: Private data supplied by the party generating the key.
    ///
    /// - Returns: The derived symmetric key.
    ///
    /// - Throws: An error if any issues occur during the derivation process.
    public static func deriveKey(
        z: Data,
        keyDataLen: Int,
        algorithmID: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        suppPubInfo: Data = Data(),
        suppPrivInfo: Data = Data(),
        tag: Data = Data()
    ) throws -> Data {
        // Calculate the hash length in bits.
        let hashLen = H.Digest.byteCount * 8

        // Check that the key data length is valid.
        guard keyDataLen > 0, UInt64(keyDataLen) <= UInt64(hashLen) * UInt64(UInt32.max) else {
            throw ConcatKDFError.invalidInput
        }

        let modLen = keyDataLen % hashLen

        // Calculate the number of iterations.
        let reps = UInt64(ceil(Double(keyDataLen) / Double(hashLen)))

        // Check that the number of iterations is valid.
        guard reps <= UInt32.max else {
            throw ConcatKDFError.invalidInput
        }

        // Concatenate the data.
        let concatenatedData = z + algorithmID + partyUInfo + partyVInfo + suppPubInfo + suppPrivInfo + tag

        // Calculate the input length for the hash function.
        let hashInputLength = (UInt32.bitWidth / 8) + concatenatedData.count

        // Check that the hash input length is valid.
        guard hashInputLength <= H.maxInputLength else {
            throw ConcatKDFError.invalidInput
        }

        // Perform the key derivation.
        var derivedKeyingMaterial = Data()
        for counter in 1 ..< reps {
            let kI = H.hash(data: UInt32(counter).bigEndian.dataRepresentation + concatenatedData)
            derivedKeyingMaterial += kI
        }

        // Calculate the last key value.
        var kLast: Data
        let kLastDigest = H.hash(data: UInt32(reps).bigEndian.dataRepresentation + concatenatedData)
        if modLen == 0 {
            kLast = kLastDigest.withUnsafeBytes { Data($0) }
        } else {
            kLast = kLastDigest.withUnsafeBytes { Data($0) }.prefixBits(of: modLen)
        }
        derivedKeyingMaterial += kLast

        // Return the derived key.
        return derivedKeyingMaterial
    }
}

private extension Data {
    /// Returns a new Data instance that contains the leftmost `count` bits of the original Data instance.
    ///
    /// - Parameter count: The number of bits to take from the left of the Data instance.
    /// - Returns: A new Data instance that contains the leftmost `count` bits of the original Data instance.
    func prefixBits(of count: Int) -> Data {
        // Return an empty Data instance if count is 0.
        guard count > 0 else {
            return .init()
        }

        // Calculate the number of bytes needed to store `count` bits.
        let byteCount = (count + 7) / 8

        // Calculate the mask to clear any unnecessary bits in the last byte.
        let mask = UInt8((1 << (byteCount * 8 - count)) - 1)

        // Take the leftmost `byteCount` bytes from the original Data instance.
        var bytes = [UInt8](prefix(byteCount))

        // If there are any bits left in the last byte that are not part of the prefix, clear them using the mask.
        if count % 8 != 0 {
            bytes[byteCount - 1] &= mask
        }

        return Data(bytes)
    }
}
