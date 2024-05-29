import Foundation
import JSONWebToken

struct MockExampleClaims: JWTRegisteredFieldsClaims, Codable {
    let iss: String?
    let sub: String?
    let aud: [String]?
    let exp: Date?
    let nbf: Date?
    let iat: Date?
    let jti: String?
    let testClaim: String?
    
    init(
        iss: String? = nil,
        sub: String? = nil,
        aud: [String]? = nil,
        exp: Date? = nil,
        nbf: Date? = nil,
        iat: Date? = nil,
        jti: String? = nil,
        testClaim: String? = nil
    ) {
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.exp = exp
        self.nbf = nbf
        self.iat = iat
        self.jti = jti
        self.testClaim = testClaim
    }
    
    func validateExtraClaims() throws {}
}
