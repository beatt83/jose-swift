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

@testable import JSONWebAlgorithms
import JSONWebKey
import Tools
import secp256k1
import XCTest

final class Secp256k1Tests: XCTestCase {

    func testSecp256k1Cycle() throws {
        let payload = "Test".data(using: .utf8)!
        let key = JWK.testingES256KSigningPair
        let signature = try ES256KSigner().sign(data: payload, key: key)
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signature,
            key: key
        ))
    }
    
    func testSecp256k1BouncyCastleSignatureVerify() throws {
        let payload = try "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJub25jZSI6IjQ3YmM5ZmMwLWVhODAtNDlmOC04OTcxLWJjYzY0MmJmZDNjMCIsImlzcyI6ImRpZDpwcmlzbTphZjJlNGJiOWU1MTRmODg5ZTdkNTY2MDZjNmYzZWVhYmNmMDgxZTc0ZTQ4NDMwN2Q3NTQ4Mzg0Y2ZiOTE4ZTdlOkNzY0JDc1FCRW1RS0QyRjFkR2hsYm5ScFkyRjBhVzl1TUJBRVFrOEtDWE5sWTNBeU5UWnJNUklnTHM1aFNjUG50REY2WGY2RElhNVFoNkp5OUZpR1FVdzdEMi16UHZSWXdmTWFJTGZGX0k0bDktZkNiX1NtS3pEaDZaQnhPbzZXX0FrN3htbTRDQ1ZENUZfLUVsd0tCMjFoYzNSbGNqQVFBVUpQQ2dselpXTndNalUyYXpFU0lDN09ZVW5ENTdReGVsMy1neUd1VUllaWN2Ulloa0ZNT3c5dnN6NzBXTUh6R2lDM3hmeU9KZmZud21fMHBpc3c0ZW1RY1RxT2x2d0pPOFpwdUFnbFEtUmZfZyIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9wcmVzZW50YXRpb25zXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXX0sImF1ZCI6ImRvbWFpbiJ9".tryToData()
        
        let publicKeyBase64 = "BC7OYUnD57Qxel3-gyGuUIeicvRYhkFMOw9vsz70WMHzt8X8jiX358Jv9KYrMOHpkHE6jpb8CTvGabgIJUPkX_4"
        let publicKeyRaw = try Base64URL.decode(publicKeyBase64)
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: publicKeyRaw, format: .uncompressed)
        let sigantureBase64 = "MEQCIGRozcub8jmgwj32UaqY26JXD2Vw91pjP1boIyIFYWNgAiANARaJ_PnNCnTFFYUgajzml8kIhyIPQsVOchQDQz1RMA=="
        let signatureRaw = try Base64URL.decode(sigantureBase64)
        let swiftSigantureBase64 = "MEQCIGBjYQUiI-hWP2Na93BlD1ei25iqUfY9wqA58pvLzWhkAiAwUT1DAxRyTsVCDyKHCMmX5jxqIIUVxXQKzfn8iRYBDQ"
        let swiftSignatureRaw = try Base64URL.decode(swiftSigantureBase64)
        
        print(swiftSignatureRaw.toHexString())
        print(signatureRaw.toHexString())
        
        // Activate bouncy castle signature fail safe
        ES256KVerifier.bouncyCastleFailSafe = true
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: swiftSignatureRaw,
            key: publicKey.jwkRepresentation
        ))
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signatureRaw,
            key: publicKey.jwkRepresentation
        ))
    }
    
    func testSecp256k1BouncyCastleSignatureVerifyFailIfFeatureNotActive() throws {
        let payload = try "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJub25jZSI6IjQ3YmM5ZmMwLWVhODAtNDlmOC04OTcxLWJjYzY0MmJmZDNjMCIsImlzcyI6ImRpZDpwcmlzbTphZjJlNGJiOWU1MTRmODg5ZTdkNTY2MDZjNmYzZWVhYmNmMDgxZTc0ZTQ4NDMwN2Q3NTQ4Mzg0Y2ZiOTE4ZTdlOkNzY0JDc1FCRW1RS0QyRjFkR2hsYm5ScFkyRjBhVzl1TUJBRVFrOEtDWE5sWTNBeU5UWnJNUklnTHM1aFNjUG50REY2WGY2RElhNVFoNkp5OUZpR1FVdzdEMi16UHZSWXdmTWFJTGZGX0k0bDktZkNiX1NtS3pEaDZaQnhPbzZXX0FrN3htbTRDQ1ZENUZfLUVsd0tCMjFoYzNSbGNqQVFBVUpQQ2dselpXTndNalUyYXpFU0lDN09ZVW5ENTdReGVsMy1neUd1VUllaWN2Ulloa0ZNT3c5dnN6NzBXTUh6R2lDM3hmeU9KZmZud21fMHBpc3c0ZW1RY1RxT2x2d0pPOFpwdUFnbFEtUmZfZyIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9wcmVzZW50YXRpb25zXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXX0sImF1ZCI6ImRvbWFpbiJ9".tryToData()
        
        let publicKeyBase64 = "BC7OYUnD57Qxel3-gyGuUIeicvRYhkFMOw9vsz70WMHzt8X8jiX358Jv9KYrMOHpkHE6jpb8CTvGabgIJUPkX_4"
        let publicKeyRaw = try Base64URL.decode(publicKeyBase64)
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: publicKeyRaw, format: .uncompressed)
        let sigantureBase64 = "MEQCIGRozcub8jmgwj32UaqY26JXD2Vw91pjP1boIyIFYWNgAiANARaJ_PnNCnTFFYUgajzml8kIhyIPQsVOchQDQz1RMA=="
        let signatureRaw = try Base64URL.decode(sigantureBase64)
        let swiftSigantureBase64 = "MEQCIGBjYQUiI-hWP2Na93BlD1ei25iqUfY9wqA58pvLzWhkAiAwUT1DAxRyTsVCDyKHCMmX5jxqIIUVxXQKzfn8iRYBDQ"
        let swiftSignatureRaw = try Base64URL.decode(swiftSigantureBase64)
        
        ES256KVerifier.bouncyCastleFailSafe = false
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: swiftSignatureRaw,
            key: publicKey.jwkRepresentation
        ))
        
        XCTAssertFalse(try ES256KVerifier().verify(
            data: payload,
            signature: signatureRaw,
            key: publicKey.jwkRepresentation
        ))
    }
    
    func testSecp256k1CycleDerSignature() throws {
        let payload = "Test".data(using: .utf8)!
        let key = try secp256k1.Signing.PrivateKey(format: .uncompressed)
        ES256KSigner.outputFormat = .der
        
        let signature = try ES256KSigner().sign(data: payload, key: key.jwkRepresentation)
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signature,
            key: key.jwkRepresentation
        ))
    }
    
    func testSecp256k1CycleInvertedRS() throws {
        let payload = "Test".data(using: .utf8)!
        let key = try secp256k1.Signing.PrivateKey(format: .uncompressed)
        ES256KSigner.invertedBytesR_S = true
        
        let signature = try ES256KSigner().sign(data: payload, key: key.jwkRepresentation)
        
        ES256KVerifier.bouncyCastleFailSafe = true
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signature,
            key: key.jwkRepresentation
        ))
    }
    
    func testSecp256k1SignatureFromJSLibrary() throws {
        let payload = try "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6cHJpc206MGYzN2Y2YmRmZWNlMzQzNzJmMzE3YmM5NDQyNzY5YzI0Yzk1ZmNkYjQzZDAzOTNiOTZiOGQ3YWEwODBlZDBiNzpDcmtCQ3JZQkVqb0tCbUYxZEdndE1SQUVTaTRLQ1hObFkzQXlOVFpyTVJJaEF2TWkxYUZZaTdOUlFWQ00zU2s2TjBvQkhIOXlabUhUcGtOT0tyd1QzYWdVRWpzS0IybHpjM1ZsTFRFUUFrb3VDZ2x6WldOd01qVTJhekVTSVFLSkp2UkloYjZLWG9iTnhWQnhaS2ZyMkdCcnNsc0lUb1doSVFCUDEyMS1yaEk3Q2dkdFlYTjBaWEl3RUFGS0xnb0pjMlZqY0RJMU5tc3hFaUVDRXI2QkJMbFVEcjFMcHdJZ1JLcHZZQ1BYUkRfWFh5SFpTbWdVTXMxZlpVMCIsInN1YiI6ImRpZDpwcmlzbTpjNzVlYjA4ZmQ2ZjUyOTcxNmUxYzBhZWZhNmQ2NDBkNDgyNTk2ODFjMjk5ZTMyMDNiYWUzZGRmMjMzNjU3MzY3OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSnFKNWNSZmhqMUpybXlxVjlFcWNEdTBWdGRGR1VmV2VxRVB4cEtvWEFsa0dpQ3NLY1lmTVZPX1dlM1l1TlBmZzB5VUlrUHdaYU81TmpWYWl3OTFpcUs0Y2hKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUpxSjVjUmZoajFKcm15cVY5RXFjRHUwVnRkRkdVZldlcUVQeHBLb1hBbGtHaUNzS2NZZk1WT19XZTNZdU5QZmcweVVJa1B3WmFPNU5qVmFpdzkxaXFLNGNnIiwibmJmIjoxNzEzNzg4OTA0LCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJlbWFpbEFkZHJlc3MiOiJjb3Jwb3JhdGVAZG9tYWluLmNvbSIsImRyaXZpbmdDbGFzcyI6MSwiZHJpdmluZ0xpY2Vuc2VJRCI6IkVTLTEyMzQ1Njc4OTAiLCJpZCI6ImRpZDpwcmlzbTpjNzVlYjA4ZmQ2ZjUyOTcxNmUxYzBhZWZhNmQ2NDBkNDgyNTk2ODFjMjk5ZTMyMDNiYWUzZGRmMjMzNjU3MzY3OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSnFKNWNSZmhqMUpybXlxVjlFcWNEdTBWdGRGR1VmV2VxRVB4cEtvWEFsa0dpQ3NLY1lmTVZPX1dlM1l1TlBmZzB5VUlrUHdaYU81TmpWYWl3OTFpcUs0Y2hKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUpxSjVjUmZoajFKcm15cVY5RXFjRHUwVnRkRkdVZldlcUVQeHBLb1hBbGtHaUNzS2NZZk1WT19XZTNZdU5QZmcweVVJa1B3WmFPNU5qVmFpdzkxaXFLNGNnIiwiZGF0ZU9mSXNzdWFuY2UiOiIyMDIzLTAxLTAxVDAyOjAyOjAyWiJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJzdGF0dXNQdXJwb3NlIjoiUmV2b2NhdGlvbiIsInN0YXR1c0xpc3RJbmRleCI6MywiaWQiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUjMyIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMUVudHJ5Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUifX19".tryToData()
        
        let publicKeyX = try Base64URL.decode("iSb0SIW-il6GzcVQcWSn69hga7JbCE6FoSEAT9dtfq4")
        let publicKeyY = try Base64URL.decode("9FcLWxguRJYRCVcuN7AHDo8wePDUVDI9UrvMSaKXbiw")
        let publicKeyRaw = [0x04] + publicKeyX + publicKeyY
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: publicKeyRaw, format: .uncompressed)
        let sigantureBase64 = "uijHd6DMBrfDq_-K2fhB17Tm4eI4twLFMu18Lz_xpfF1K3yuJ58CkUqKAb_HNORrP9e4jc8BTbqGwDzk7utB9A"
        let signatureRaw = try Base64URL.decode(sigantureBase64)
        
        ES256KVerifier.bouncyCastleFailSafe = true
        
        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signatureRaw,
            key: publicKey.jwkRepresentation
        ))
    }
    
    func testSecp256k1JSLibrarySignatureVerifyFailIfFeatureNotActive() throws {
        let payload = try "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6cHJpc206MGYzN2Y2YmRmZWNlMzQzNzJmMzE3YmM5NDQyNzY5YzI0Yzk1ZmNkYjQzZDAzOTNiOTZiOGQ3YWEwODBlZDBiNzpDcmtCQ3JZQkVqb0tCbUYxZEdndE1SQUVTaTRLQ1hObFkzQXlOVFpyTVJJaEF2TWkxYUZZaTdOUlFWQ00zU2s2TjBvQkhIOXlabUhUcGtOT0tyd1QzYWdVRWpzS0IybHpjM1ZsTFRFUUFrb3VDZ2x6WldOd01qVTJhekVTSVFLSkp2UkloYjZLWG9iTnhWQnhaS2ZyMkdCcnNsc0lUb1doSVFCUDEyMS1yaEk3Q2dkdFlYTjBaWEl3RUFGS0xnb0pjMlZqY0RJMU5tc3hFaUVDRXI2QkJMbFVEcjFMcHdJZ1JLcHZZQ1BYUkRfWFh5SFpTbWdVTXMxZlpVMCIsInN1YiI6ImRpZDpwcmlzbTpjNzVlYjA4ZmQ2ZjUyOTcxNmUxYzBhZWZhNmQ2NDBkNDgyNTk2ODFjMjk5ZTMyMDNiYWUzZGRmMjMzNjU3MzY3OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSnFKNWNSZmhqMUpybXlxVjlFcWNEdTBWdGRGR1VmV2VxRVB4cEtvWEFsa0dpQ3NLY1lmTVZPX1dlM1l1TlBmZzB5VUlrUHdaYU81TmpWYWl3OTFpcUs0Y2hKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUpxSjVjUmZoajFKcm15cVY5RXFjRHUwVnRkRkdVZldlcUVQeHBLb1hBbGtHaUNzS2NZZk1WT19XZTNZdU5QZmcweVVJa1B3WmFPNU5qVmFpdzkxaXFLNGNnIiwibmJmIjoxNzEzNzg4OTA0LCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJlbWFpbEFkZHJlc3MiOiJjb3Jwb3JhdGVAZG9tYWluLmNvbSIsImRyaXZpbmdDbGFzcyI6MSwiZHJpdmluZ0xpY2Vuc2VJRCI6IkVTLTEyMzQ1Njc4OTAiLCJpZCI6ImRpZDpwcmlzbTpjNzVlYjA4ZmQ2ZjUyOTcxNmUxYzBhZWZhNmQ2NDBkNDgyNTk2ODFjMjk5ZTMyMDNiYWUzZGRmMjMzNjU3MzY3OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSnFKNWNSZmhqMUpybXlxVjlFcWNEdTBWdGRGR1VmV2VxRVB4cEtvWEFsa0dpQ3NLY1lmTVZPX1dlM1l1TlBmZzB5VUlrUHdaYU81TmpWYWl3OTFpcUs0Y2hKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUpxSjVjUmZoajFKcm15cVY5RXFjRHUwVnRkRkdVZldlcUVQeHBLb1hBbGtHaUNzS2NZZk1WT19XZTNZdU5QZmcweVVJa1B3WmFPNU5qVmFpdzkxaXFLNGNnIiwiZGF0ZU9mSXNzdWFuY2UiOiIyMDIzLTAxLTAxVDAyOjAyOjAyWiJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJzdGF0dXNQdXJwb3NlIjoiUmV2b2NhdGlvbiIsInN0YXR1c0xpc3RJbmRleCI6MywiaWQiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUjMyIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMUVudHJ5Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUifX19".tryToData()
        
        let publicKeyX = try Base64URL.decode("iSb0SIW-il6GzcVQcWSn69hga7JbCE6FoSEAT9dtfq4")
        let publicKeyY = try Base64URL.decode("9FcLWxguRJYRCVcuN7AHDo8wePDUVDI9UrvMSaKXbiw")
        let publicKeyRaw = [0x04] + publicKeyX + publicKeyY
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: publicKeyRaw, format: .uncompressed)
        let sigantureBase64 = "uijHd6DMBrfDq_-K2fhB17Tm4eI4twLFMu18Lz_xpfF1K3yuJ58CkUqKAb_HNORrP9e4jc8BTbqGwDzk7utB9A"
        let signatureRaw = try Base64URL.decode(sigantureBase64)
        
        ES256KVerifier.bouncyCastleFailSafe = false
        
        XCTAssertFalse(try ES256KVerifier().verify(
            data: payload,
            signature: signatureRaw,
            key: publicKey.jwkRepresentation
        ))
    }

    func testNotNormalizedBouncyCastleSignatureValidation() async throws {
        let payload = try "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6cHJpc206MGYzN2Y2YmRmZWNlMzQzNzJmMzE3YmM5NDQyNzY5YzI0Yzk1ZmNkYjQzZDAzOTNiOTZiOGQ3YWEwODBlZDBiNzpDcmtCQ3JZQkVqb0tCbUYxZEdndE1SQUVTaTRLQ1hObFkzQXlOVFpyTVJJaEF2TWkxYUZZaTdOUlFWQ00zU2s2TjBvQkhIOXlabUhUcGtOT0tyd1QzYWdVRWpzS0IybHpjM1ZsTFRFUUFrb3VDZ2x6WldOd01qVTJhekVTSVFLSkp2UkloYjZLWG9iTnhWQnhaS2ZyMkdCcnNsc0lUb1doSVFCUDEyMS1yaEk3Q2dkdFlYTjBaWEl3RUFGS0xnb0pjMlZqY0RJMU5tc3hFaUVDRXI2QkJMbFVEcjFMcHdJZ1JLcHZZQ1BYUkRfWFh5SFpTbWdVTXMxZlpVMCIsInN1YiI6ImRpZDpwcmlzbTpiYWQyNDgzNDA2NjU5MmIwMDgwYjlmMWYyZjkxZjA1ZmNiZDU0MzQxMDlkZTIwMTM3YmRiOWE0ZWE4N2E4NjQ4OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSDNWNzdRb3dXWWZpN1BHdFZTSjBIZVdjcVlwdmxzanNydUN1ZUhITDByZUdpRHl4OWVBN0lQdVgyLUExMkxHZktFczJZTGJoUm1ILUdWbzFNUndZdUYta0JKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUgzVjc3UW93V1lmaTdQR3RWU0owSGVXY3FZcHZsc2pzcnVDdWVISEwwcmVHaUR5eDllQTdJUHVYMi1BMTJMR2ZLRXMyWUxiaFJtSC1HVm8xTVJ3WXVGLWtBIiwibmJmIjoxNzEzODYyMjk4LCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJlbWFpbEFkZHJlc3MiOiJjb3Jwb3JhdGVAZG9tYWluLmNvbSIsImRyaXZpbmdDbGFzcyI6MSwiZHJpdmluZ0xpY2Vuc2VJRCI6IkVTLTEyMzQ1Njc4OTAiLCJpZCI6ImRpZDpwcmlzbTpiYWQyNDgzNDA2NjU5MmIwMDgwYjlmMWYyZjkxZjA1ZmNiZDU0MzQxMDlkZTIwMTM3YmRiOWE0ZWE4N2E4NjQ4OkN0OEJDdHdCRW5RS0gyRjFkR2hsYm5ScFkyRjBhVzl1WVhWMGFHVnVkR2xqWVhScGIyNUxaWGtRQkVKUENnbHpaV053TWpVMmF6RVNJSDNWNzdRb3dXWWZpN1BHdFZTSjBIZVdjcVlwdmxzanNydUN1ZUhITDByZUdpRHl4OWVBN0lQdVgyLUExMkxHZktFczJZTGJoUm1ILUdWbzFNUndZdUYta0JKa0NnOXRZWE4wWlhKdFlYTjBaWEpMWlhrUUFVSlBDZ2x6WldOd01qVTJhekVTSUgzVjc3UW93V1lmaTdQR3RWU0owSGVXY3FZcHZsc2pzcnVDdWVISEwwcmVHaUR5eDllQTdJUHVYMi1BMTJMR2ZLRXMyWUxiaFJtSC1HVm8xTVJ3WXVGLWtBIiwiZGF0ZU9mSXNzdWFuY2UiOiIyMDIzLTAxLTAxVDAyOjAyOjAyWiJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJzdGF0dXNQdXJwb3NlIjoiUmV2b2NhdGlvbiIsInN0YXR1c0xpc3RJbmRleCI6NCwiaWQiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUjNCIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMUVudHJ5Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOlwvXC8xOTIuMTY4LjEuNDQ6ODAwMFwvcHJpc20tYWdlbnRcL2NyZWRlbnRpYWwtc3RhdHVzXC9jMDkxOGViNi1lZGIzLTRjMTUtYWM4OS0yZDk5MTZmMjFmYjUifX19".tryToData()

        let publicKeyRaw = Data(base64Encoded: "BIkm9EiFvopehs3FUHFkp+vYYGuyWwhOhaEhAE/XbX6u9FcLWxguRJYRCVcuN7AHDo8wePDUVDI9UrvMSaKXbiw=")!
        let publicKey = try secp256k1.Signing.PublicKey(dataRepresentation: publicKeyRaw, format: .uncompressed)
        let sigantureBase64 = "gKPlzHeuO0NryO1f_iHzxKUtyyD6e_woWNoK2QsEBGuhQw-tkJpKVvBzK0F-z7bdG0nj6xWZBmlJ7ctsVexYPg"
        let signatureRaw = try Base64URL.decode(sigantureBase64)

        ES256KVerifier.bouncyCastleFailSafe = true

        XCTAssertTrue(try ES256KVerifier().verify(
            data: payload,
            signature: signatureRaw,
            key: publicKey.jwkRepresentation
        ))
    }
}
