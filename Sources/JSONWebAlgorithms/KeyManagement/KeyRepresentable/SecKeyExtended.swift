import Crypto
@preconcurrency import CryptoSwift
import Foundation
import JSONWebKey
import Security

public struct SecKeyExtended {
    public enum SupportedKeyType {
        case rsa
        case p256
        case p384
        case p521
    }
    
    public enum KeyUsage {
        case sign
        case keyAgreement
        case unknown
    }
    
    public enum SecKeyError: Error {
        case invalidKey
        case unsupportedKeyType
        case keyDataExtractionFailed
    }
    
    public let key: SecKey
    public let keyType: SupportedKeyType
    public let isPrivate: Bool
    public let keyData: Data
    public let keyUsage: KeyUsage
    
    public init(secKey: SecKey) throws {
        self.key = secKey
        
        // Get key attributes
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any] else {
            throw SecKeyError.invalidKey
        }
        
        // Determine key type
        guard let keyTypeString = attributes[kSecAttrKeyType as String] as? String else {
            throw SecKeyError.unsupportedKeyType
        }
        
        switch keyTypeString as CFString {
        case kSecAttrKeyTypeRSA:
            self.keyType = .rsa
        case kSecAttrKeyTypeECSECPrimeRandom:
            guard let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int else {
                throw SecKeyError.unsupportedKeyType
            }
            switch keySize {
            case 256:
                self.keyType = .p256
            case 384:
                self.keyType = .p384
            case 521:
                self.keyType = .p521
            default:
                throw SecKeyError.unsupportedKeyType
            }
        default:
            throw SecKeyError.unsupportedKeyType
        }
        
        // Determine if the key is private or public
        guard let keyClass = attributes[kSecAttrKeyClass as String] as? String else {
            throw SecKeyError.invalidKey
        }
        self.isPrivate = (keyClass == (kSecAttrKeyClassPrivate as String))
        
        // Extract key data
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw CryptoError.securityLayerError(
                internalStatus: (error?.takeUnretainedValue() as? NSError)?.code,
                internalError: (error?.takeUnretainedValue() as? NSError)
            )
        }
        
        self.keyData = keyData
        
        // Determine key usage
        let canSign = (attributes[kSecAttrCanSign as String] as? Bool) ?? false
        let canDerive = (attributes[kSecAttrCanDerive as String] as? Bool) ?? false
        
        if canSign {
            self.keyUsage = .sign
        } else if canDerive {
            self.keyUsage = .keyAgreement
        } else {
            self.keyUsage = .unknown
        }
    }
    
    public func jwk() throws -> JWK {
        return try buildJWK()
    }
    
    private func buildJWK() throws -> JWK {
        switch keyType {
        case .rsa:
            return try buildRSA()
        case .p256:
            return try buildP256Key()
        case .p384:
            return try buildP384Key()
        case .p521:
            return try buildP521Key()
        }
    }
    
    private func buildRSA() throws -> JWK {
        return try CryptoSwift.RSA(rawRepresentation: keyData).jwkRepresentation
    }
    
    private func buildP256Key() throws -> JWK {
        if isPrivate {
            switch keyUsage {
            case .sign, .unknown:
                return try P256.Signing.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            case .keyAgreement:
                return try P256.KeyAgreement.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            }
        }
        
        switch keyUsage {
        case .sign, .unknown:
            return try P256.Signing.PublicKey.init(x963Representation: keyData).jwkRepresentation
        case .keyAgreement:
            return try P256.KeyAgreement.PublicKey.init(x963Representation: keyData).jwkRepresentation
        }
    }
    
    private func buildP384Key() throws -> JWK {
        if isPrivate {
            switch keyUsage {
            case .sign, .unknown:
                return try P384.Signing.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            case .keyAgreement:
                return try P384.KeyAgreement.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            }
        }
        
        switch keyUsage {
        case .sign, .unknown:
            return try P384.Signing.PublicKey.init(x963Representation: keyData).jwkRepresentation
        case .keyAgreement:
            return try P384.KeyAgreement.PublicKey.init(x963Representation: keyData).jwkRepresentation
        }
    }
    
    private func buildP521Key() throws -> JWK {
        if isPrivate {
            switch keyUsage {
            case .sign, .unknown:
                return try P521.Signing.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            case .keyAgreement:
                return try P521.KeyAgreement.PrivateKey.init(x963Representation: keyData).jwkRepresentation
            }
        }
        
        switch keyUsage {
        case .sign, .unknown:
            return try P521.Signing.PublicKey.init(x963Representation: keyData).jwkRepresentation
        case .keyAgreement:
            return try P521.KeyAgreement.PublicKey.init(x963Representation: keyData).jwkRepresentation
        }
    }
}
