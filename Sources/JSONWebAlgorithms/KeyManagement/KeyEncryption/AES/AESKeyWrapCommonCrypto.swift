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

import CommonCrypto
import Foundation

class AESKeyWrapperCommonCrypto {
    private let algorithm: CCWrappingAlgorithm = UInt32(kCCWRAPAES)
    
    func wrap(key: Data, encryptionKey: Data) throws -> Data {
        let outputSize = CCSymmetricWrappedSize(algorithm, key.count)
        var buffer = Data(count: outputSize)
        var wrappedKeyLength = outputSize
        
        let result = buffer.write(withPointerTo: encryptionKey, key) { bufferPtr, ptrs in
            CCSymmetricKeyWrap(self.algorithm,
                               CCrfc3394_iv,
                               CCrfc3394_ivLen,
                               ptrs[0],
                               encryptionKey.count,
                               ptrs[1],
                               key.count,
                               bufferPtr,
                               &wrappedKeyLength)
        }
        
        if result != kCCSuccess {
            throw CryptoError.commonCryptoError(status: result)
        }
        
        return buffer.prefix(upTo: wrappedKeyLength)
    }
    
    func unwrap(key: Data, encryptionKey: Data) throws -> Data {
        let outputSize = CCSymmetricUnwrappedSize(algorithm, key.count)
        var buffer = Data(count: outputSize)
        var unwrappedKeyLength = outputSize
        
        let result = buffer.write(withPointerTo: encryptionKey, key) { bufferPtr, ptrs in
            CCSymmetricKeyUnwrap(self.algorithm,
                                 CCrfc3394_iv,
                                 CCrfc3394_ivLen,
                                 ptrs[0],
                                 encryptionKey.count,
                                 ptrs[1],
                                 key.count,
                                 bufferPtr,
                                 &unwrappedKeyLength)
        }
        
        if result != kCCSuccess {
            throw CryptoError.commonCryptoError(status: result)
        }
        
        return buffer.prefix(upTo: unwrappedKeyLength)
    }
}

fileprivate extension Data {
    func write<T>(withPointerTo args: Data..., body: (UnsafeMutablePointer<UInt8>, [UnsafePointer<UInt8>]) -> T) -> T {
        return self.withUnsafeBytes { bufferRawPtr -> T in
            let bufferPtr = bufferRawPtr.bindMemory(to: UInt8.self).baseAddress!
            var ptrs: [UnsafePointer<UInt8>] = []
            for arg in args {
                arg.withUnsafeBytes { argRawPtr in
                    let argPtr = argRawPtr.bindMemory(to: UInt8.self).baseAddress!
                    ptrs.append(argPtr)
                }
            }
            return bufferPtr.withMemoryRebound(to: UInt8.self, capacity: count) { reboundBufferPtr in
                body(UnsafeMutablePointer(mutating: reboundBufferPtr), ptrs)
            }
        }
    }
}
