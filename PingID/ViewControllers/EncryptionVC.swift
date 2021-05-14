//
//  EncryptionVC.swift
//  PingID
//
//  Created by Roi Kedarya on 10/05/2021.
//

import Foundation
import UIKit
import UserNotifications
import CommonCrypto

class EncryptionVC: UIViewController {
        
    @IBOutlet weak var field: UITextField!
    var userNotificationCenter: UNUserNotificationCenter?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupVC()
    }
    
    private func setupVC() {
        field.returnKeyType = .done
        field.delegate = self
        let gesture = UITapGestureRecognizer.init(target: self, action: #selector(removeKeyboard))
        self.view.addGestureRecognizer(gesture)
        userNotificationCenter = UNUserNotificationCenter.current()
        self.requestNotificationAuthorization()
        self.sendNotification()
    }
    
    @objc private func removeKeyboard() {
        field.resignFirstResponder()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        //field.becomeFirstResponder()
    }
    
    @IBAction func SendButtonPressed(_ sender: Any) {
        removeKeyboard()
        if let text = field.text, !text.isEmpty {
            do {
                let encriptedData = try encrypt(text)
                if let encriptedData = encriptedData, let keyPair = getKeyPair(for: "Sign") {
                    do {
                        let signature = try sign(encryptedData: encriptedData, privateKey: keyPair.privateKey)
                    } catch {
                        print("Signing Error")
                    }
                }
            } catch {
               print("Encryption Error")
            }
        } else {
            print("Please enter a message")
        }
    }
    
    
    /*
     func uses the SecKeyCreateEncryptedData for encryption
     If something goes wrong, the function returns nil cipher text and produces an error object that indicates the cause of failure
     */
    private func encrypt(_ string:String) throws -> Data? {
        if let keyPair = getKeyPair(for: "RSA-Encryption") {
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

//    private func encrypt(_ string:String) throws -> [UInt8]? {
//        if let keyPair = generateKeyPair(for: "RSA-Encryption") {
//            let blockSize = SecKeyGetBlockSize(keyPair.publicKey)
//            let textData = [UInt8](string.utf8)
//            let textLength = string.count
//            var encryptedData: [UInt8] = [UInt8].init(repeating: 0, count: blockSize)
//            var encryptedDataLength: Int = blockSize
//            // encrypting
//            let encryptOsStatus: OSStatus = SecKeyEncrypt(keyPair.publicKey, .PKCS1, textData, textLength, &encryptedData, &encryptedDataLength)
//
//            if encryptOsStatus != noErr {
//                throw cryptoError.encrypt
//                print("Encryption Error")
//            } else {
//                return encryptedData
//            }
//        }
//        return nil
//    }
    
    /*
     func uses the SecKeyCreateSignature for signing
     If something goes wrong, the function returns a nil signature and populates the error reference with a CFError object that explains the failure
     */
    private func sign(encryptedData: Data, privateKey:SecKey) throws -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        var error: Unmanaged<CFError>?
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw cryptoError.sign
        }
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        return signature
    }
    
//    func generateKeyPair () -> (publicKey: SecKey, privateKey: SecKey)? {
//        let parameters: [NSObject: NSObject] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 1024 as NSObject]
//        var publicKey: SecKey?
//        var privateKey: SecKey?
//        let statusCode: OSStatus = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
//        if statusCode == noErr, let publicKey = publicKey, let privateKey = privateKey {
//            print("Key pair generated OK")
//            return (publicKey, privateKey)
//        } else {
//            return nil
//        }
//    }
    
    
    /*
     
     */
    private func getKeyPair(for tag: String) -> (publicKey: SecKey, privateKey: SecKey)? {
        let query = [kSecAttrApplicationTag as String: tag.data(using: .utf8)!] as CFDictionary
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        if status == errSecSuccess {
            let privateKey = item as! SecKey
            if let publicKey = SecKeyCopyPublicKey(privateKey) {
                return (publicKey, privateKey)
            }
        }
            return generateKeyPair(for: tag)
    }
    
    private func generateKeyPair (for tag: String) -> (publicKey: SecKey, privateKey: SecKey)? {
        var error: Unmanaged<CFError>?
        let params: [String:Any] = [
            kSecAttrType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 1024,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                                            kSecAttrApplicationTag as String: tag]
        ]
        do {
            guard let privateKey = SecKeyCreateRandomKey(params as CFDictionary, &error),
                  let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw error!.takeRetainedValue() as Error
            }
            storeAndUpdate(key: privateKey, InKeyChainFor: tag)
            return (publicKey,privateKey)
        } catch {
            print(error)
            return nil
        }
    }
    
    private func storeAndUpdate(key: SecKey, InKeyChainFor tag: String) {
        let tagData = tag.data(using: .utf8)!
        let query = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tagData,
                                       kSecValueRef as String: key] as CFDictionary
        let status: OSStatus
        var result: String
        if isKeyAlreadyOnKeychain(query) {
            let attributesToUpdate = [kSecValueRef as String: key] as CFDictionary
            status = SecItemUpdate(query, attributesToUpdate)
            result = "Key Updated"
        } else {
            status = SecItemAdd(query, nil)
            result = "Key Added"
        }
        guard status == errSecSuccess else {
            print("Error adding key to KeyChain")
            return
        }
        print(result)
    }
    
    private func deleteKeyFromKeychain(_ query: CFDictionary) {
        
    }
    
    private func isKeyAlreadyOnKeychain(_ query: CFDictionary) -> Bool {
        let status = SecItemCopyMatching(query, nil)
        return status == errSecSuccess
    }
    
    deinit {
        if let text = field.text, !text.isEmpty {
            self.field.text = nil
        }
    }
    
}

extension EncryptionVC: UITextFieldDelegate {
    func textFieldDidEndEditing(_ textField: UITextField) {
        removeKeyboard()
    }
    
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        removeKeyboard()
        return true
    }
}

extension EncryptionVC {
    func requestNotificationAuthorization() {
        let authOptions = UNAuthorizationOptions.init(arrayLiteral: .alert, .badge, .sound)
        guard let userNotificationCenter = self.userNotificationCenter else {
            return
        }
        userNotificationCenter.requestAuthorization(options: authOptions) { (success, error) in
            if let error = error {
                print("Error: ", error)
            }
        }
    }

    func sendNotification() {
        // Create new notifcation content instance
        let notificationContent = UNMutableNotificationContent()

        // Add the content to the notification content
        notificationContent.title = "PingId"
        notificationContent.body = "Test body"
        notificationContent.badge = nil

        // Add an attachment to the notification content
        if let url = Bundle.main.url(forResource: "dune",
                                        withExtension: "png") {
            if let attachment = try? UNNotificationAttachment(identifier: "dune",
                                                                url: url,
                                                                options: nil) {
                notificationContent.attachments = [attachment]
            }
        }
    }
}



enum cryptoError: Error {
    case sign
    case encrypt
    case decrypt
    case unsupportedAlgorithm
}
