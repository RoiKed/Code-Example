//
//  DecryptionVC.swift
//  PingID
//
//  Created by Roi Kedarya on 15/05/2021.
//

import Foundation
import UIKit

protocol keychainHandler {
    func deleteFromKeychain(key: SecKey) throws
    func storeAndUpdateToKeychain(using key: SecKey,_ tag: String)
    func isExistInKeychain(_ query: CFDictionary) -> Bool
    func getKey(for query: CFDictionary) -> SecKey?
}

class DecryptionVC: UIViewController {
    
    var content: UNNotificationContent?
    var delegate: keychainHandler?
    var sig: Data?
    var encryptedmsg: Data?
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        //let presentingVC = self.presentingViewController
        do {
            try getMsg()
        } catch {
            
        }
    }
    
    private func getQuery(for tag: String) -> CFDictionary {
        let query = [
            kSecClass as String: kSecClassKey,
            kSecReturnRef as String: true,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!
        ] as CFDictionary
        return query
    }
    
    func getMsg() throws {
        if let content = content {
            let title = content.title
            let messageString = content.body
            let signatureString = content.subtitle
            let signature = Data(signatureString.utf8) as CFData
            //print("signature is \(signature)")
            let encryptedMessage = Data(messageString.utf8) as CFData
            //print("encryptedMessage is \(encryptedMessage)")
            do {
                print("messageString is \(messageString)")
                let testString = String(decoding: self.encryptedmsg!, as: UTF8.self)
                print("test string is   \(testString)")
                if try isSignatureVerified(signature, encryptedMessage) {
                    do {
                        if let decryptedMessage = try decrypt(encryptedMessage as CFData) {
                            print(decryptedMessage)
                        }
                    } catch {
                        print("Decryption Failed")
                    }
                }
            } catch {
                print("signature verification Failed")
            }
        }
    }
    private func decrypt(_ data:CFData) throws -> String? {
        if let delegate = delegate {
            let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
            let query = getQuery(for: Query.encrypt.rawValue)
            if let privateKey = delegate.getKey(for: query) {
                var error: Unmanaged<CFError>?
                guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, data, &error) as Data?
                else {
                    throw error!.takeRetainedValue() as Error
                }
                return String(decoding: decryptedData, as: UTF8.self)
            }
        }
        return nil
    }
    
    private func isSignatureVerified(_ signature: CFData, _ encryptedMsg: CFData) throws -> Bool {
        var retVal = false
        if let delegate = delegate {
            let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
            let query = getQuery(for: Query.sign.rawValue)
            if let privateKey = delegate.getKey(for: query) {
                guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
                    print("key is not suitable for an operation using a certain algorithm.")
                    throw cryptoError.verificationError
                }
                if let publicKey = SecKeyCopyPublicKey(privateKey) {
                    var error: Unmanaged<CFError>?
                    
                    guard SecKeyVerifySignature(publicKey, algorithm, encryptedMsg as CFData, signature as CFData, &error)
                    else {
                        throw error!.takeRetainedValue() as Error
                    }
                    if error == nil {
                        retVal = true
                    }
                    
                }
            }
        }
        return retVal
    }
}



