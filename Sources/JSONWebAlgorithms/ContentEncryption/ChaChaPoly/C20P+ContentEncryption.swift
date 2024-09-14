import CryptoKit
import Foundation

/// `C20P` provides methods to encrypt and decrypt data using the ChaCha20-Poly1305 algorithm.
public struct C20P: ContentEncryptor, ContentDecryptor {
    /// The content encryption algorithm used, represented as a string.
    public let contentEncryptionAlgorithm: String = ContentEncryptionAlgorithm.c20P.rawValue
    /// The size of the initialization vector in bits.
    public let initializationVectorSizeInBits: Int = ContentEncryptionAlgorithm.c20P.initializationVectorSizeInBits
    /// The size of the content encryption key (CEK) in bits.
    public let cekKeySize: Int = ContentEncryptionAlgorithm.c20P.keySizeInBits
    
    /// Generates a random initialization vector.
    /// - Throws: An error if the random data generation fails.
    /// - Returns: A data object containing the initialization vector.
    public func generateInitializationVector() throws -> Data {
        try SecureRandom.secureRandomData(count: initializationVectorSizeInBits / 8)
    }
    
    /// Generates a random content encryption key (CEK).
    /// - Throws: An error if the random data generation fails.
    /// - Returns: A data object containing the CEK.
    public func generateCEK() throws -> Data {
        try SecureRandom.secureRandomData(count: cekKeySize / 8)
    }
    
    /// Encrypts the payload using the ChaCha20-Poly1305 algorithm.
    /// - Parameters:
    ///   - payload: The data to be encrypted.
    ///   - key: The encryption key.
    ///   - arguments: Additional encryption arguments, such as initialization vector and additional authenticated data.
    /// - Throws: An error if the encryption fails or if required arguments are missing or of incorrect size.
    /// - Returns: A `ContentEncryptionResult` containing the cipher text and authentication tag.
    public func encrypt(
        payload: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> ContentEncryptionResult {
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
    
    /// Decrypts the cipher text using the ChaCha20-Poly1305 algorithm.
    /// - Parameters:
    ///   - cipher: The data to be decrypted.
    ///   - key: The decryption key.
    ///   - arguments: Additional decryption arguments, such as initialization vector and authentication tag.
    /// - Throws: An error if the decryption fails or if required arguments are missing.
    /// - Returns: The decrypted data.
    public func decrypt(
        cipher: Data,
        using key: Data,
        arguments: [ContentEncryptionArguments]
    ) throws -> Data {
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
