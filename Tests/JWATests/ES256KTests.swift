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
}
