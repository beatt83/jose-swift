import CryptoKit
import Foundation

struct C20PKW: ContentEncryptor, ContentDecryptor {
    
    let contentEncryptionAlgorithm: String = ContentEncryptionAlgorithm.c20PKW.rawValue
    let initializationVectorSizeInBits: Int = ContentEncryptionAlgorithm.c20PKW.initializationVectorSizeInBits
    let cekKeySize: Int = ContentEncryptionAlgorithm.c20PKW.keySizeInBits
    
    func generateInitializationVector() throws -> Data {
        try SecureRandom.secureRandomData(count: initializationVectorSizeInBits / 8)
    }
    
    func generateCEK() throws -> Data {
        try SecureRandom.secureRandomData(count: cekKeySize / 8)
    }
    
    func encrypt(payload: Data, using key: Data, arguments: [ContentEncryptionArguments]) throws -> ContentEncryptionResult {
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard iv.count * 8 == initializationVectorSizeInBits else {
            throw CryptoError.initializationVectorWrongSize(sizeInBits: initializationVectorSizeInBits)
        }
        
        guard let aad = arguments.additionalAuthenticationData else {
            throw CryptoError.missingAdditionalAuthenticatingData
        }
        
        let aead = try ChaChaPoly.seal(
            payload,
            using: .init(data: key),
            nonce: .init(data: iv),
            authenticating: aad
        )
        
        return .init(cipher: aead.ciphertext, authenticationData: aead.tag)
    }
    
    func decrypt(cipher: Data, using key: Data, arguments: [ContentEncryptionArguments]) throws -> Data {
        guard let iv = arguments.initializationVector else {
            throw CryptoError.missingInitializationVector
        }
        
        guard let tag = arguments.authenticationTag else {
            throw CryptoError.missingAuthenticationTag
        }
        
        guard let aad = arguments.additionalAuthenticationData else {
            throw CryptoError.missingAdditionalAuthenticatingData
        }
        
        return try ChaChaPoly.open(.init(
            nonce: .init(data: iv),
            ciphertext: cipher,
            tag: tag
        ), using: .init(data: key), authenticating: aad)
    }
}
