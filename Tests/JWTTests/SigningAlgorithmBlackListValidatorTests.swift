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

import JSONWebAlgorithms
import JSONWebKey
@testable import JSONWebToken
import JSONWebSignature
import JSONWebEncryption
import XCTest

final class SigningAlgorithmBlackListValidatorTests: XCTestCase {
    
    func testSingleAlgorithmBlackListedFailsValidation() throws {
        let header = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.none, type: "JWT")
        let payload = try #"{"test":"value"}"#.tryToData()
        
        let jwt = try JWT(payload: payload, format: .jws(.init(protectedHeader: header, data: payload, signature: Data())))

        XCTAssertThrowsError(try SigningAlgorithmBlackListValidator(blackList: [.none]).isValid(jwt.jwtString))
    }
    
    func testMultipleAlgorithmBlackListedFailsValidation() throws {
        let header1 = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.none, type: "JWT")
        let payload1 = try #"{"test":"value"}"#.tryToData()
        
        let header2 = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.ES256, type: "JWT")
        let payload2 = try #"{"test":"value"}"#.tryToData()
        
        let jwt1 = try JWT(payload: payload1, format: .jws(.init(protectedHeader: header1, data: payload1, signature: Data())))
        let jwt2 = try JWT(payload: payload2, format: .jws(.init(protectedHeader: header2, data: payload2, signature: Data())))
        
        let validator = SigningAlgorithmBlackListValidator(blackList: [.none, .ES256])
        XCTAssertThrowsError(try validator.isValid(jwt1.jwtString))
        XCTAssertThrowsError(try validator.isValid(jwt2.jwtString))
    }
    
    func testAlgorithmNotBlackListedValidationSuccess() throws {
        let header = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.ES256, type: "JWT")
        let payload = try #"{"test":"value"}"#.tryToData()
        
        let jwt = try JWT(payload: payload, format: .jws(.init(protectedHeader: header, data: payload, signature: Data())))

        XCTAssertNoThrow(try SigningAlgorithmBlackListValidator(blackList: [.none]).isValid(jwt.jwtString))
    }
    
    func testMultipleAlgorithmnOTBlackListedValidationSuccess() throws {
        let header1 = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.RS384, type: "JWT")
        let payload1 = try #"{"test":"value"}"#.tryToData()
        
        let header2 = DefaultJWSHeaderImpl(algorithm: SigningAlgorithm.RS256, type: "JWT")
        let payload2 = try #"{"test":"value"}"#.tryToData()
        
        let jwt1 = try JWT(payload: payload1, format: .jws(.init(protectedHeader: header1, data: payload1, signature: Data())))
        let jwt2 = try JWT(payload: payload2, format: .jws(.init(protectedHeader: header2, data: payload2, signature: Data())))
        
        let validator = SigningAlgorithmBlackListValidator(blackList: [.ES256, .ES384])
        XCTAssertNoThrow(try validator.isValid(jwt1.jwtString))
        XCTAssertNoThrow(try validator.isValid(jwt2.jwtString))
    }
    
    func testAlgorithmIsMissingFailsValidation() throws {
        let header = DefaultJWSHeaderImpl(type: "JWT")
        let payload = try #"{"test":"value"}"#.tryToData()
        
        let jwt = try JWT(payload: payload, format: .jws(.init(protectedHeader: header, data: payload, signature: Data())))

        XCTAssertThrowsError(try SigningAlgorithmBlackListValidator(blackList: [.none], algorithmRequired: true).isValid(jwt.jwtString))
    }
    
    func testAlgorithmIsMissingButNotRequiredValidationSuccess() throws {
        let header = DefaultJWSHeaderImpl(type: "JWT")
        let payload = try #"{"test":"value"}"#.tryToData()
        
        let jwt = try JWT(payload: payload, format: .jws(.init(protectedHeader: header, data: payload, signature: Data())))

        XCTAssertNoThrow(try SigningAlgorithmBlackListValidator(blackList: [.none], algorithmRequired: false).isValid(jwt.jwtString))
    }
}
