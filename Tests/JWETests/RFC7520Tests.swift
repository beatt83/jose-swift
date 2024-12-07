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
@testable import JSONWebEncryption
import JSONWebKey
import XCTest
import Tools

final class RFC7520Tests: XCTestCase {
    
    let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
    
    let rsaKeyJson = """
    {
      "kty": "RSA",
      "kid": "frodo.baggins@hobbiton.example",
      "use": "enc",
      "n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
          HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
          6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
          NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
          R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
          pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
          VotGlvMQ",
      "e": "AQAB",
      "d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
          bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
          5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
          Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
          1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
          miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
          pzj85bQQ",
      "p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
          oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
          7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
          2VFmU",
      "q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
          F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
          9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
          d6Et0",
      "dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
          QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
          RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
          lo0rYU",
      "dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
          pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
          CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
          TkXlHE",
      "qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
          lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
          Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
          2bQ_mM"
    }
    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
    
    let p384KeyJson = """
        {
          "kty": "EC",
          "kid": "peregrin.took@tuckborough.example",
          "use": "enc",
          "crv": "P-384",
          "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQL
              pe2FpxBmu2",
          "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-
              SkgaFL1ETP",
          "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0Idn
              YK2xDlZh-j"
        }
        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
    
    func testSection_5_1() throws {
        let recipientJWK = try JSONDecoder().decode(JWK.self, from: rsaKeyJson)
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .rsa1_5,
                encodingAlgorithm: .a128CBCHS256,
                keyID: recipientJWK.keyID
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo"),
            initializationVector: Base64URL.decode("bbd5sTkYwhAIqfHsx8DayA"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let compactSerializationTestVector = """
            eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
            V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
            .
            laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF
            vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G
            Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG
            TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl
            zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh
            MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw
            .
            bbd5sTkYwhAIqfHsx8DayA
            .
            0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r
            aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O
            WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV
            yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0
            zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2
            O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW
            i7lzA6BP430m
            .
            kvKuFBXHe5mQr4lqgobAUg
            """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: compactSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_2() throws {
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "RSA",
              "kid": "samwise.gamgee@hobbiton.example",
              "use": "enc",
              "n": "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRr
                  I4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-Fy
                  XJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnk
                  Nrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeSt
                  sqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M
                  5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIU
                  e7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBOD
                  FskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb
                  86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqB
                  SAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhO
                  OnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDa
                  iCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnT
                  yC0xhWBlsolZE",
              "e": "AQAB",
              "alg": "RSA-OAEP",
              "d": "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bx
                  cc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq
                  -B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT
                  2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9E
                  A-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876
                  DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIj
                  h1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r
                  -MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yD
                  F-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1L
                  oomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W
                  _IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28
                  S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c
                  9WsWgRzI-K8gE",
              "p": "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKgh
                  vM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsY
                  a_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3m
                  Y46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-
                  RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9s
                  fbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgP
                  gWCv5HoQ",
              "q": "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6Zy
                  KQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDc
                  qssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYG
                  RuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJ
                  aPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EX
                  e2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJ
                  JlXXnH8Q",
              "dp": "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xn
                  x5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQ
                  J_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72F
                  ZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3i
                  XjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGm
                  pKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9Lc
                  nwwT0jvoQ",
              "dq": "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1
                  VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM
                  1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fg
                  dyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrI
                  ChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2
                  AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iz
                  nBNCeOUIQ",
              "qi": "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCc
                  iRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80
                  oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMw
                  QqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl
                  27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4
                  UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq
                  8EzqZEKIA"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .rsaOAEP,
                encodingAlgorithm: .a256GCM,
                keyID: recipientJWK.keyID
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("mYMfsggkTAm0TbvtlFh2hyoXnbEzJQjMxmgLN3d8xXA"),
            initializationVector: Base64URL.decode("-nBoKLH0YkLZPSI9"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let compactSerializationTestVector = """
            eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG
            9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0
            .
            rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQi
            beYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyu
            cvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58
            -Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8Bpx
            KdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pK
            IIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7
            pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQ
            fOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe3
            8UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU
            06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5
            Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDR
            s
            .
            -nBoKLH0YkLZPSI9
            .
            o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgR
            L-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEw
            P7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8
            iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML
            7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSV
            maPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw
            .
            UCGiqJxhBI3IFVdPalHHvA
            """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: compactSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_4() throws {
        let recipientJWK = try JSONDecoder().decode(JWK.self, from: p384KeyJson)
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .ecdhESA128KW,
                encodingAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID,
                ephemeralPublicKey: JSONDecoder().decode(
                    JWK.self,
                    from: """
                    {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuE
                          DsQ6wNdNg3",
                      "y": "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-
                          JdaY8tb7E0",
                      "d": "D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8W
                          fwhinUfWJg"
                    }
                    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                )
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("Nou2ueKlP70ZXDbq9UrRwg"),
            initializationVector: Base64URL.decode("mH-G2zVqgztUtnW_"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH
        Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt
        Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH
        hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy
        ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT
        h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0
        .
        0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2
        .
        mH-G2zVqgztUtnW_
        .
        tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cP
        WJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0
        IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkc
        Y9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w0
        3XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu
        07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ
        .
        WuGzxmcreYjpHGJoa17EBg
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_5() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "EC",
              "kid": "meriadoc.brandybuck@buckland.example",
              "use": "enc",
              "crv": "P-256",
              "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
              "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
              "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .ecdhES,
                encodingAlgorithm: .a128CBCHS256,
                keyID: recipientJWK.keyID,
                ephemeralPublicKey: JSONDecoder().decode(
                    JWK.self,
                    from: """
                    {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
                      "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
                      "d": "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM"
                    }
                    """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                )
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: nil,
            initializationVector: Base64URL.decode("yc9N8v5sYyv3iGQT926IUg"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW
        NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi
        LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF
        lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0
        RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ
        .
        .
        yc9N8v5sYyv3iGQT926IUg
        .
        BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9
        IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e
        vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-
        IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI
        -sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7
        MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61
        95_JGG2m9Csg
        .
        WCCkNa-x4BeB9hIDIfFuhg
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_6() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
              "use": "enc",
              "alg": "A128GCM",
              "k": "XctOhJAkA-pD9Lh7ZgW_2A"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let sharedSymmetricKey = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
              "use": "enc",
              "alg": "A128GCM",
              "k": "XctOhJAkA-pD9Lh7ZgW_2A"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .direct,
                encodingAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: sharedSymmetricKey.key!,
            initializationVector: Base64URL.decode("refa467QzzKx6QAB"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK,
            sharedKey: sharedSymmetricKey
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT
        diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0
        .
        .
        refa467QzzKx6QAB
        .
        JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y
        hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM
        DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_
        BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5
        g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn
        ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp
        .
        vbb32Xvllea2OtmHAdccRQ
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK,
            sharedKey: sharedSymmetricKey
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_7() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
              "use": "enc",
              "alg": "A256GCMKW",
              "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a256GCMKW,
                encodingAlgorithm: .a128CBCHS256,
                keyID: recipientJWK.keyID,
                initializationVector: Base64URL.decode("KkYT0GX_2jHlfqN_")
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("UWxARpat23nL9ReIj4WG3D1ee9I4r-Mv5QLuFXdy_rE"),
            initializationVector: Base64URL.decode("gz6NjyEFNm_vm8Gj6FwoFQ"),
            additionalAuthenticationData: nil
        )
        
        let decrypted = try JWE.decrypt(
            compactString: serialization.compactSerialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYj
        IwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3
        IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1Ni
        J9
        .
        lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok
        .
        gz6NjyEFNm_vm8Gj6FwoFQ
        .
        Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaE
        eVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCz
        LjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFq
        hpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQaJtvJmSMFuEOSAzw9Hde
        b6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k0Jtj
        xAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR
        1B-gxpNk3xWU
        .
        DKW7jrb4WaRSNfbXVPlT5g
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_8() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a128KW,
                encodingAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("aY5_Ghmk9KxWPBLu_glx1w"),
            initializationVector: Base64URL.decode("Qx0pmsDa8KnJc9Jo"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0
        .
        CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx
        .
        Qx0pmsDa8KnJc9Jo
        .
        AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6
        1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe
        F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE
        wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p
        uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa
        a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF
        .
        ER7MWJZ1FBI_NKvn7Zb1Lw
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_9() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a128KW,
                encodingAlgorithm: .a128GCM,
                compressionAlgorithm: .deflate,
                keyID: recipientJWK.keyID
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("hC-MpLZSuwWv8sexS6ydfw"),
            initializationVector: Base64URL.decode("p9pUq6XHY0jfEZIl"),
            additionalAuthenticationData: nil
        ).compactSerialization
        
        let decrypted = try JWE.decrypt(
            compactString: serialization,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC
        04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0
        .
        5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi
        .
        p9pUq6XHY0jfEZIl
        .
        HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyez
        SPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0
        m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBK
        hpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw
        .
        VILuUwuIxaLVmh5X-T7kmA
        """.replacingWhiteSpacesAndNewLines()
        
        let decryptedTestVector = try JWE.decrypt(
            compactString: expectedSerializationTestVector,
            recipientKey: recipientJWK
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_10() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE.jsonSerialization(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a128KW,
                encodingAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            recipientKeys: [recipientJWK],
            cek: Base64URL.decode("75m1ALsYv10pZTKPWrsqdg"),
            initializationVector: Base64URL.decode("veCx9ece2orS7c_N"),
            additionalAuthenticationData: Base64URL.decode("""
            WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fS
            widGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0Iixb
            IkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LC
            J0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d
            """.replacingWhiteSpacesAndNewLines())
        )
        
        let decrypted = try JWE.decrypt(
            jweJson: try JSONEncoder.jose.encode(serialization),
            senderKey: nil,
            recipientKey: recipientJWK,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decrypted)
        
        let expectedSerializationTestVector = """
        {
          "recipients": [
            {
              "encrypted_key": "4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X"
            }
          ],
          "protected": "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04Mz
              MyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn
              0",
          "iv": "veCx9ece2orS7c_N",
          "aad": "WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxb
              ImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4i
              LHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIs
              IiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVy
              Iix7fSwidGV4dCIsIk0iXV1d",
          "ciphertext": "Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0
              Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14
              T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fz
              OI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrs
              LNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy
              2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3
              X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV",
          "tag": "vOaH_Rajnpy_3hOtqvZHRA"
        }
        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        
        let decryptedTestVector = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_11() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(
                encodingAlgorithm: .a128GCM
            ),
            unprotectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a128KW,
                keyID: recipientJWK.keyID
            ),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("WDgEptBmQs9ouUvArz6x6g"),
            initializationVector: Base64URL.decode("WgEJsDS9bkoXQ3nR")
        ).compactSerialization
        
        let expectedSerializationTestVector = """
        {
          "recipients": [
            {
              "encrypted_key": "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"
            }
          ],
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8"
          },
          "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
          "iv": "WgEJsDS9bkoXQ3nR",
          "ciphertext": "lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2D
              M3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9O
              CCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6
              uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5
              g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU
              4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3
              HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",
          "tag": "fNYLqpUe84KD45lvDiaBAQ"
        }
        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        
        let decryptedTestVector = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_12() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
              "use": "enc",
              "alg": "A128KW",
              "k": "GZy6sIZ6wl9NJOKB-jnmVQ"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE(
            payload: payload,
            unprotectedHeader: DefaultJWEHeaderImpl(
                keyManagementAlgorithm: .a128KW,
                encodingAlgorithm: .a128GCM,
                keyID: recipientJWK.keyID
            ),
            senderKey: nil,
            recipientKey: recipientJWK,
            cek: Base64URL.decode("WDgEptBmQs9ouUvArz6x6g"),
            initializationVector: Base64URL.decode("WgEJsDS9bkoXQ3nR")
        ).compactSerialization
        
        let expectedSerializationTestVector = """
        {
          "recipients": [
            {
              "encrypted_key": "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"
            }
          ],
          "unprotected": {
            "alg": "A128KW",
            "kid": "81b20965-8332-43d9-a468-82160ad91ac8"
          },
          "protected": "eyJlbmMiOiJBMTI4R0NNIn0",
          "iv": "WgEJsDS9bkoXQ3nR",
          "ciphertext": "lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2D
              M3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9O
              CCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6
              uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5
              g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU
              4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3
              HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",
          "tag": "fNYLqpUe84KD45lvDiaBAQ"
        }
        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        
        let decryptedTestVector = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decryptedTestVector)
    }
    
    func testSection_5_13() throws {
        let payload = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        
        let recipientJWK1 = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "RSA",
              "kid": "frodo.baggins@hobbiton.example",
              "use": "enc",
              "n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
                  HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
                  6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
                  NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
                  R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
                  pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
                  VotGlvMQ",
              "e": "AQAB",
              "d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
                  bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
                  5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
                  Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
                  1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
                  miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
                  pzj85bQQ",
              "p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
                  oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
                  7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
                  2VFmU",
              "q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
                  F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
                  9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
                  d6Et0",
              "dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
                  QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
                  RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
                  lo0rYU",
              "dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
                  pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
                  CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
                  TkXlHE",
              "qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
                  lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
                  Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
                  2bQ_mM"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let recipientJWK2 = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "EC",
              "kid": "peregrin.took@tuckborough.example",
              "use": "enc",
              "crv": "P-384",
              "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQL
                  pe2FpxBmu2",
              "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-
                  SkgaFL1ETP",
              "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0Idn
                  YK2xDlZh-j"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let recipientJWK3 = try JSONDecoder().decode(
            JWK.self,
            from: """
            {
              "kty": "oct",
              "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
              "use": "enc",
              "alg": "A256GCMKW",
              "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        )
        
        let serialization = try JWE.jsonSerialization(
            payload: payload,
            protectedHeader: DefaultJWEHeaderImpl(encodingAlgorithm: .a128CBCHS256),
            unprotectedHeader: DefaultJWEHeaderImpl(contentType: "text/plain"),
            recipients: [
                (DefaultJWEHeaderImpl(
                    keyManagementAlgorithm: .rsa1_5,
                    keyID: recipientJWK1.keyID
                ), recipientJWK1),
                (DefaultJWEHeaderImpl(
                    keyManagementAlgorithm: .ecdhESA256KW,
                    keyID: recipientJWK2.keyID,
                    ephemeralPublicKey: JSONDecoder().decode(
                        JWK.self,
                        from: """
                        {
                          "kty": "EC",
                          "crv": "P-384",
                          "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2Dt
                              MRb25Ma2CX",
                          "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw9
                              1fzZ84pbfm",
                          "d": "1DKHfTv-PiifVw2VBHM_ZiVcwOMxkOyANS_lQHJcrDxVY3jhVCvZPw
                              MxJKIE793C"
                        }
                        """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
                    )
                ), recipientJWK2),
                (DefaultJWEHeaderImpl(
                    keyManagementAlgorithm: .a256GCMKW,
                    keyID: recipientJWK3.keyID,
                    initializationVector: Base64URL.decode("AvpeoPZ9Ncn9mkBn"),
                    authenticationTag: Base64URL.decode("59Nqh1LlYtVIhfD3pgRGvw")
                ), recipientJWK3),
            ],
            cek: Base64URL.decode("zXayeJ4gvm8NJr3IUInyokTUO-LbQNKEhe_zWlYbdpQ"),
            initializationVector: Base64URL.decode("VgEIHY20EnzUtZFl2RpB1g")
        )
        
        let jsonData = try JSONEncoder.jose.encode(serialization)
        
        let decryptedRecipient1 = try JWE.decrypt(
            jweJson: jsonData,
            senderKey: nil,
            recipientKey: recipientJWK1,
            sharedKey: nil
        )
        
        let decryptedRecipient2 = try JWE.decrypt(
            jweJson: jsonData,
            senderKey: nil,
            recipientKey: recipientJWK2,
            sharedKey: nil
        )
        
        let decryptedRecipient3 = try JWE.decrypt(
            jweJson: jsonData,
            senderKey: nil,
            recipientKey: recipientJWK3,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decryptedRecipient1)
        XCTAssertEqual(payload, decryptedRecipient2)
        XCTAssertEqual(payload, decryptedRecipient3)
        
        let expectedSerializationTestVector = """
            {
              "recipients": [
                {
                  "encrypted_key": "dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zj
                      wj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-
                      vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076
                      DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S
                      1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbe
                      YSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n
                      5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ",
                  "header": {
                    "alg": "RSA1_5",
                    "kid": "frodo.baggins@hobbiton.example"
                  }
                },
                {
                  "encrypted_key": "ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHi
                      xJuw_elY4gSSId_w",
                  "header": {
                    "alg": "ECDH-ES+A256KW",
                    "kid": "peregrin.took@tuckborough.example",
                    "epk": {
                      "kty": "EC",
                      "crv": "P-384",
                      "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhs
                          E2xAn2DtMRb25Ma2CX",
                      "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEj
                          I1pOMbw91fzZ84pbfm"
                    }
                  }
                },
                {
                  "encrypted_key": "a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-Wy
                      TpS1E",
                  "header": {
                    "alg": "A256GCMKW",
                    "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                    "tag": "59Nqh1LlYtVIhfD3pgRGvw",
                    "iv": "AvpeoPZ9Ncn9mkBn"
                  }
                }
              ],
              "unprotected": {
                "cty": "text/plain"
              },
              "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
              "iv": "VgEIHY20EnzUtZFl2RpB1g",
              "ciphertext": "ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK
                  04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM
                  9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSa
                  P6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7p
                  kt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQ
                  rgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3
                  ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLCht
                  azE",
              "tag": "BESYyFN7T09KY7i8zKs5_g"
            }
            """.replacingWhiteSpacesAndNewLines().data(using: .utf8)!
        
        let decryptedTestVectorRecipient1 = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK1,
            sharedKey: nil
        )
        
        let decryptedTestVectorRecipient2 = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK2,
            sharedKey: nil
        )
        
        let decryptedTestVectorRecipient3 = try JWE.decrypt(
            jweJson: expectedSerializationTestVector,
            senderKey: nil,
            recipientKey: recipientJWK3,
            sharedKey: nil
        )
        
        XCTAssertEqual(payload, decryptedTestVectorRecipient1)
        XCTAssertEqual(payload, decryptedTestVectorRecipient2)
        XCTAssertEqual(payload, decryptedTestVectorRecipient3)
    }
}
