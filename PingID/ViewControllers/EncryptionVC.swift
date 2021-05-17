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
    @IBOutlet weak var imageView: UIImageView!
    
    var userNotificationCenter: UNUserNotificationCenter = UNUserNotificationCenter.current()
    var signatureForMsg: String?
    var encryptedDataForMsg: String?
    var sig:Data?
    var encryptedmsg:Data?
    
    private lazy var mainStoryboard: UIStoryboard = {
        let mainStoryboard = UIStoryboard(name: "Main", bundle:nil)
        return mainStoryboard
    }()
    
    lazy var decryptionViewController: DecryptionVC = {
        let decryptionViewController = mainStoryboard.instantiateViewController(identifier: "decryptionViewController") as? DecryptionVC ?? DecryptionVC()
        return decryptionViewController
    }()
        
    override func viewDidLoad() {
        super.viewDidLoad()
        setupVC()
    }
    
    private func setupVC() {
        field.returnKeyType = .done
        field.delegate = self
        if let image = UIImage(named: "secure.jpg") {
            //self.imageView = UIImageView(frame: CGRectZero)
            self.imageView.contentMode = .scaleAspectFill
            self.imageView.image = image
            self.view.backgroundColor = UIColor(patternImage: image)
            self.view.contentMode = .center
        }
        let gesture = UITapGestureRecognizer.init(target: self, action: #selector(removeKeyboard))
        self.view.addGestureRecognizer(gesture)
        userNotificationCenter.delegate = self
        self.requestNotificationAuthorization()
        self.addObserverForAppInBackground()
    }
    
    @objc func removeKeyboard() {
        field.resignFirstResponder()
    }
    
    @IBAction func SendButtonPressed(_ sender: Any) {
        removeKeyboard()
        if let text = field.text, !text.isEmpty {
            do {
                let encryptedData = try encrypt(text)
                if let encryptedData = encryptedData, let keyPair = getKeyPair(for: Query.sign.rawValue) {
                    do {
                        if let signature = try sign(encryptedData: encryptedData, privateKey: keyPair.privateKey) {
                            let signatureString = String(decoding: signature, as: UTF8.self)
                            let backToSignature = Data(signatureString.utf8)
                            print(backToSignature == signature)
                            
                            let backToSignatureString = String(decoding: backToSignature, as: UTF8.self)
                            print(signatureString == backToSignatureString)
                            self.sig = signature
                            self.encryptedmsg = encryptedData
                            signatureForMsg = String(decoding: signature, as: UTF8.self)
                            print(signatureForMsg! == signatureString)
                            encryptedDataForMsg = String(decoding: encryptedData, as: UTF8.self)
                            
                            clearText() // clear the text only if it was already encrypted
                        }
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
     If something goes wrong, the function returns nil cipher text
     and produces an error object that indicates the cause of failure
     */
    private func encrypt(_ string:String) throws -> Data? {
        if let keyPair = getKeyPair(for: Query.encrypt.rawValue) {
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
    
    private func clearText() {
        if let text = field.text, !text.isEmpty {
            field.text = nil
        }
    }
    
    /*
     func uses the SecKeyCreateSignature for signing
     If something goes wrong, the function returns a nil signature and
     populates the error reference with a CFError object that explains the failure
     */
    private func sign(encryptedData: Data, privateKey:SecKey) throws -> Data? {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        var error: Unmanaged<CFError>?
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw cryptoError.signError
        }
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        print("signature is \(signature as CFData)")
        print("encryptedData is \(encryptedData as CFData)")
        if let publicKey = SecKeyCopyPublicKey(privateKey) {
            var error: Unmanaged<CFError>?
            guard SecKeyVerifySignature(publicKey,
                                        algorithm,
                                        encryptedData as CFData,
                                        signature as CFData,
                                        &error)
            else {
                                            throw error!.takeRetainedValue() as Error
            }
        }
        return signature
    }
    
    /*
     If the keyPair exist in the key chain  - return the keyPair,
     otherwise, genrate a new pair that will be stored in the key chain
     */
    private func getKeyPair(for tag: String) -> (publicKey: SecKey, privateKey: SecKey)? {
        let query = [kSecClass as String: kSecClassKey,
                     kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                     kSecReturnRef as String: true,
                     kSecAttrApplicationTag as String: tag.data(using: .utf8)!] as CFDictionary
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
            storeAndUpdateToKeychain(using: privateKey, tag)
            return (publicKey,privateKey)
        } catch {
            print(error)
            return nil
        }
    }
}

