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
import ZlibSwift

enum ZipError : Error {
    case compressionFailed
    case decompressionFailed
}

/// `Zip` provides methods to compress and decompress data using zlib.
public struct Zip: ContentCompressor, ContentDecompressor {
    /// Compresses the input data using zlib.
    /// - Parameter input: The data to be compressed.
    /// - Throws: An error if the compression fails.
    /// - Returns: The compressed data.
    public func compress(input: Data) throws -> Data {
        guard let compressed = input.zCompressed else {
            throw ZipError.compressionFailed
        }
        return compressed;
    }
    
    /// Decompresses the input data using zlib.
    /// - Parameter input: The data to be decompressed.
    /// - Throws: An error if the decompression fails.
    /// - Returns: The decompressed data.
    public func decompress(input: Data) throws -> Data {
        guard let decompressed = input.zDecompressed else {
            throw ZipError.decompressionFailed

        }
        return decompressed;
    }
}
