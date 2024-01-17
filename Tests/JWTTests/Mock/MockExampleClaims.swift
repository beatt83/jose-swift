import Foundation
import JSONWebToken

struct MockExampleClaims: JWTRegisteredFieldsClaims {
    let issuer: String?
    let subject: String?
    let audience: [String]?
    let expirationTime: Date?
    let notBeforeTime: Date?
    let issuedAt: Date?
    let jwtID: String?
    let testClaim: String?
    
    init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: [String]? = nil,
        expirationTime: Date? = nil,
        notBeforeTime: Date? = nil,
        issuedAt: Date? = nil,
        jwtID: String? = nil,
        testClaim: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expirationTime = expirationTime
        self.notBeforeTime = notBeforeTime
        self.issuedAt = issuedAt
        self.jwtID = jwtID
        self.testClaim = testClaim
    }
    
    func validateExtraClaims() throws {}
}
