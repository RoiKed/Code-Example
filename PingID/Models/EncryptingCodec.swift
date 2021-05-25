//
//  EncryptingCodec.swift
//  PingID
//
//  Created by Roi Kedarya on 25/05/2021.
//

import Foundation


class EncryptingCodec {
    
    let keysManager = KeychainManager()
    
    /*
     func uses the SecKeyCreateEncryptedData for encryption
     If something goes wrong, the function returns nil cipher text
     and produces an error object that indicates the cause of failure
     */
     func encrypt(_ string:String) throws -> Data? {
        if let keyPair = keysManager.getKeyPair(for: Query.encrypt.rawValue) {
            let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
            guard SecKeyIsAlgorithmSupported(keyPair.publicKey, .encrypt, algorithm) else {
                throw cryptoError.unsupportedAlgorithm
            }
            let stringData = string.data(using: .utf8)! as CFData
            var error: Unmanaged<CFError>?
            guard let encryptedText = SecKeyCreateEncryptedData(keyPair.publicKey, algorithm, stringData, &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            return encryptedText
        } else {
            return nil
        }
    }
    
    /*
     func uses the SecKeyCreateSignature for signing
     If something goes wrong, the function returns a nil signature and
     populates the error reference with a CFError object that explains the failure
     */
    func sign(encryptedData: Data?) throws -> Data? {
        var signedData:Data?
        if let encryptedData = encryptedData, let keyPair = keysManager.getKeyPair(for: Query.sign.rawValue) {
            let privateKey = keyPair.privateKey
            let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
            var error: Unmanaged<CFError>?
            guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
                throw cryptoError.signError
            }
            guard let signed = SecKeyCreateSignature(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
                throw error!.takeRetainedValue()
            }
            signedData = signed
        }
        return signedData
    }
    
    func decrypt(_ data:CFData) throws -> String? {
        let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
        let query = keysManager.getQuery(for: Query.encrypt.rawValue)
        if let privateKey = keysManager.getKey(for: query) {
            var error: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, data, &error) as Data?
            else {
                throw error!.takeRetainedValue() as Error
            }
            return String(decoding: decryptedData, as: UTF8.self)
        }
        return nil
    }
    
    func isSignatureVerified(_ signature: CFData, _ encryptedMsg: CFData) throws -> Bool {
        var retVal = false
        do {
            retVal = try keysManager.isSignatureVerified(signature, encryptedMsg)
        } catch {
            print("key is not suitable for an operation using a certain algorithm.")
        }
        return retVal
    }
}
