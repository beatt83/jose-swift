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

/// `ContentCompressor` is a protocol defining the functionality for compressing data.
public protocol ContentCompressor {
    /// Compresses the provided input data.
    /// - Parameter input: The data to be compressed.
    /// - Returns: The compressed data.
    /// - Throws: An error if compression fails.
    func compress(input: Data) throws -> Data
}

/// `ContentDecompressor` is a protocol defining the functionality for decompressing data.
public protocol ContentDecompressor {
    /// Decompresses the provided input data.
    /// - Parameter input: The data to be decompressed.
    /// - Returns: The decompressed data.
    /// - Throws: An error if decompression fails.
    func decompress(input: Data) throws -> Data
}
