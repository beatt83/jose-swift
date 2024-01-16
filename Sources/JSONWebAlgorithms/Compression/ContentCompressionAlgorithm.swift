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

/// `ContentCompressionAlgorithm` is an enumeration representing the supported content compression algorithms.
public enum ContentCompressionAlgorithm: String, Codable {
    /// The DEFLATE compression algorithm.
    case deflate = "DEF"
}

/// Extension of `ContentCompressionAlgorithm` to provide compressor and decompressor functionalities.
extension ContentCompressionAlgorithm {
    /// Provides a `ContentCompressor` instance based on the selected compression algorithm.
    /// - Returns: An instance of a compressor suitable for the algorithm.
    ///   - For `.deflate`, it returns a `Zip` compressor.
    public var compressor: ContentCompressor {
        switch self {
        case .deflate:
            return Zip()
        }
    }
    
    /// Provides a `ContentDecompressor` instance based on the selected compression algorithm.
    /// - Returns: An instance of a decompressor suitable for the algorithm.
    ///   - For `.deflate`, it returns a `Zip` decompressor.
    public var decompressor: ContentDecompressor {
        switch self {
        case .deflate:
            return Zip()
        }
    }
}
