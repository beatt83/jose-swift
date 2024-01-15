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
import JWA
import JWK

func getKeyAlgorithm(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> KeyManagementAlgorithm? {
    recipientHeader?.keyManagementAlgorithm
    ?? protectedHeader?.keyManagementAlgorithm
    ?? unprotectedHeader?.keyManagementAlgorithm
}

func getEncoding(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> ContentEncryptionAlgorithm? {
    protectedHeader?.encodingAlgorithm
    ?? recipientHeader?.encodingAlgorithm
    ?? unprotectedHeader?.encodingAlgorithm
}

func getContentCompressionAlg(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> ContentCompressionAlgorithm? {
    protectedHeader?.compressionAlgorithm
    ?? recipientHeader?.compressionAlgorithm
    ?? unprotectedHeader?.compressionAlgorithm
}

func getKeyEncryptionInitializationVector(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> Data? {
    recipientHeader?.initializationVector
    ?? protectedHeader?.initializationVector
    ?? unprotectedHeader?.initializationVector
}

func getKeyEncryptionAuthenticationTag(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> Data? {
    recipientHeader?.authenticationTag
    ?? protectedHeader?.authenticationTag
    ?? unprotectedHeader?.authenticationTag
}

func getPartyUInfo(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> Data? {
    recipientHeader?.agreementPartyUInfo
    ?? protectedHeader?.agreementPartyUInfo
    ?? unprotectedHeader?.agreementPartyUInfo
}

func getPartyVInfo(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> Data? {
    recipientHeader?.agreementPartyVInfo
    ?? protectedHeader?.agreementPartyVInfo
    ?? unprotectedHeader?.agreementPartyVInfo
}

func getEphemeralKey(
    protectedHeader: JWERegisteredFieldsHeader?,
    unprotectedHeader: JWERegisteredFieldsHeader?,
    recipientHeader: JWERegisteredFieldsHeader?
) -> JWK? {
    recipientHeader?.ephemeralPublicKey
    ?? protectedHeader?.ephemeralPublicKey
    ?? unprotectedHeader?.ephemeralPublicKey
}
