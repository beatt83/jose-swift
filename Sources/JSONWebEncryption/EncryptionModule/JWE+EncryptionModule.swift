import Foundation

public final class JWEEncryptionModuleContainer: @unchecked Sendable {
    var encryptionModule: JWEEncryptionModule
    
    public init(encryptionModule: JWEEncryptionModule) {
        self.encryptionModule = encryptionModule
    }
    
    public func setEncryptionModule(_ encryptionModule: JWEEncryptionModule) {
        self.encryptionModule = encryptionModule
    }
}

extension JWE {
    public static let encryptionModuleContainer: JWEEncryptionModuleContainer = .init(encryptionModule: .default)
}
