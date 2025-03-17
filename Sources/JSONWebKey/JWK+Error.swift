// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

public extension JWK {
    /// An error that can be thrown when working with JWKs.
    ///
    /// This enumeration defines the errors that can be thrown when working with JWKs.
    enum Error: Swift.Error, Equatable {
        /// The keys used in the JWE are incompatible.
        case jweIncompatibleKeys
        
        /// The key type is not supported.
        case notSupported

        /// The "x" component of an EC or OKP key is missing.
        case missingXComponent

        /// The "y" component of an EC key is missing.
        case missingYComponent

        /// The "d" component of an EC or RSA key is missing.
        case missingDComponent

        /// The "p" and "q" components of a RSA key is missing.
        case missingPrimesComponent

        /// The "n" component of an RSA key is missing.
        case missingNComponent

        /// The "e" component of an RSA key is missing.
        case missingEComponent

        /// The specified key ID was not found in the JWK set.
        case keyWithIDNotFound(String)

        /// The key was not found in the JWK set.
        case keyNotFound
        
        /// Error decoding PEM
        case pemDecodingError
    }
}
