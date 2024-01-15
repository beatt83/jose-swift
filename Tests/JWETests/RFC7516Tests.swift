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

import JWA
@testable import JWE
import JWK
import XCTest
import Tools

final class RFC7516Tests: XCTestCase {

    func testA_1() throws {
        let payload = "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"RSA",
             "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
                  cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
                  psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
                  sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
                  tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
                  YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
             "e":"AQAB",
             "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N
                  WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9
                  3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk
                  qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl
                  t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd
                  VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
             "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-
                  SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf
                  fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
             "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm
                  UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX
                  IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
             "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL
                  hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827
                  rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
             "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj
                  ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB
                  UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
             "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7
                  AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3
                  eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let cek = Data([
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252,
        ])
        
        let initializationVector = Data([
            227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219,
        ])
        
        let serialization = try JWE(
            payload: payload,
            keyManagementAlg: .rsaOAEP,
            encryptionAlgorithm: .a256GCM,
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: cek,
            initializationVector: initializationVector,
            additionalAuthenticationData: nil
        )
        
        let compact = serialization.compactSerialization()
        
        let jweCompact = try JWE(compactString: compact)
        let decrypted = try jweCompact.decrypt(recipientKey: recipientJWK)

        XCTAssertEqual(payload, decrypted)
    }
    
    func testA_1_7() throws {
        let payload = "The true sign of intelligence is not knowledge but imagination.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"RSA",
             "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
                  cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
                  psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
                  sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
                  tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
                  YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
             "e":"AQAB",
             "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N
                  WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9
                  3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk
                  qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl
                  t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd
                  VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
             "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-
                  SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf
                  fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
             "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm
                  UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX
                  IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
             "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL
                  hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827
                  rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
             "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj
                  ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB
                  UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
             "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7
                  AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3
                  eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let jweString = """
            eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
            OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
            ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
            Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
            mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
            1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
            6UklfCpIMfIjf7iGdXKHzg.
            48V1_ALb6US04U3b.
            5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
            SdiwkIr3ajwQzaBtQD_A.
            XFBoMYUZodetZdvTiFvSkQ
            """.replacingWhiteSpacesAndNewLines()
        
        let serialization = try JWE.decrypt(compactString: jweString, recipientKey: recipientJWK)
        
        XCTAssertEqual(try payload.tryToString(), try serialization.tryToString())
    }
    
    func testA_3() throws {
        let payload = "Live long and prosper.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"oct",
             "k":"GawgguFyGrWKav7AX4VKUg"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let cek = Data([
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
            206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
            44, 207,
        ])
        
        let iv = Data([
            3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
            101,
        ])
        
        let serialization = try JWE(
            payload: payload,
            keyManagementAlg: .a128KW,
            encryptionAlgorithm: .a128CBCHS256,
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: cek,
            initializationVector: iv,
            additionalAuthenticationData: nil
        )
        
        XCTAssertEqual(
            serialization.compactSerialization(),
            """
            eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
            6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.
            AxY8DCtDaGlsbGljb3RoZQ.
            KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.
            U0m_YmjN04DJvceFICbCVQ
            """.replacingWhiteSpacesAndNewLines()
        )
    }
    
    func testA_4() throws {
        let payload = "Live long and prosper.".data(using: .utf8)!
        
        let recipientJWK1 = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"RSA",
             "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl
                  UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre
                  cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_
                  7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI
                  Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU
                  7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
             "e":"AQAB",
             "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq
                  1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry
                  nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_
                  0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj
                  -VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj
                  T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
             "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68
                  ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP
                  krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
             "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y
                  BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN
                  -3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
             "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv
                  ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra
                  Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
             "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff
                  7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_
                  odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
             "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC
                  tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ
                  B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
             "kid":"2011-04-29"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let recipientJWK2 = try JSONDecoder().decode(
            JWK.self,
            from: """
            {"kty":"oct",
             "k":"GawgguFyGrWKav7AX4VKUg",
             "kid":"7"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let cek = Data([
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
            206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
            44, 207,
        ])
        
        let iv = try Base64URL.decode("AxY8DCtDaGlsbGljb3RoZQ")
        
        let serialization = try JWE.jsonSerialization(
            payload: payload,
            encryptionAlgorithm: .a128CBCHS256,
            unprotectedHeader: DefaultJWEHeaderImpl(jwkSetURL: "https://server.example.com/keys.jwks"),
            senderKey: nil,
            recipients: [
                (KeyManagementAlgorithm.rsa1_5, recipientJWK1),
                (KeyManagementAlgorithm.a128KW, recipientJWK2)
            ],
            cek: cek,
            initializationVector: iv,
            additionalAuthenticationData: nil
        )
        
        XCTAssertEqual(Base64URL.encode(serialization.protectedData!), "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")
        XCTAssertEqual(Base64URL.encode(serialization.initializationVector!), "AxY8DCtDaGlsbGljb3RoZQ")
        
        let validJson = """
            {
             "protected":
              "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
             "unprotected":
              {"jku":"https://server.example.com/keys.jwks"},
             "recipients":[
              {"header":
                {"alg":"RSA1_5","kid":"2011-04-29"},
               "encrypted_key":
                "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
                 kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
                 GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
                 YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
                 cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
                 wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
              {"header":
                {"alg":"A128KW","kid":"7"},
               "encrypted_key":
                "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],
             "iv":
              "AxY8DCtDaGlsbGljb3RoZQ",
             "ciphertext":
              "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
             "tag":
              "Mz-VPPyU4RlcuYv1IwIvzw"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        
        let decryption1 = try JWE.decrypt(jweJson: validJson, recipientKey: recipientJWK1)
        let decryption2 = try JWE.decrypt(jweJson: validJson, recipientKey: recipientJWK2)
        
        XCTAssertEqual(payload, decryption1)
        XCTAssertEqual(payload, decryption2)
    }
}
