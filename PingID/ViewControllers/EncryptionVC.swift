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
    @IBOutlet weak var updateLabel: UILabel!
    @IBOutlet weak var switchButton: UISwitch!
    
    var userNotificationCenter: UNUserNotificationCenter = UNUserNotificationCenter.current()
    var signedString: String?
    var encryptedDataForMsg: String?
    var updateArray = [String]()
    
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
        setBackgroundImage()
        let gesture = UITapGestureRecognizer.init(target: self, action: #selector(removeKeyboard))
        self.view.addGestureRecognizer(gesture)
        userNotificationCenter.delegate = self
        self.requestNotificationAuthorization()
        self.addObserverForAppInBackground()
    }
    
    private func setBackgroundImage() {
        if let image = UIImage(named: "secure.jpg") {
            self.imageView.contentMode = .scaleAspectFill
            self.imageView.image = image
            self.view.backgroundColor = UIColor(patternImage: image)
            self.view.contentMode = .center
        }
    }
    
    @objc func removeKeyboard() {
        field.resignFirstResponder()
    }
    
    @IBAction func SendButtonPressed(_ sender: Any) {
        removeKeyboard()
        if let text = field.text, !text.isEmpty {
            do {
                let encryptedData = try encrypt(text)
                updateArray.append("String encrypted")
                if let encryptedData = encryptedData, let keyPair = getKeyPair(for: Query.sign.rawValue) {
                    do {
                        if  let signedData = try sign(encryptedData: encryptedData, privateKey: keyPair.privateKey) {
                            updateArray.append("String signed")
                            signedString = signedData.toString()
                            encryptedDataForMsg = encryptedData.toString()
                            clearText() // clear the text only if it was already encrypted
                        }
                    } catch {
                        updateArray.append("Signing Error")
                    }
                }
            } catch {
                updateArray.append("Encryption Error")
            }
        } else {
            print("Please enter a message")
        }
        updateLabel(actions: updateArray)
    }
    
    func updateLabel(actions:[String]) {
        _ = Timer.scheduledTimer(timeInterval: 0.3, target: self, selector: #selector(update(_:)), userInfo: nil, repeats: true)
    }
    
    @objc func update(_ timer: Timer) {
        if updateArray.count > 0 {
            updateLabel.text = updateArray.remove(at: 0)
        } else {
            timer.invalidate()
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
        guard let signedData = SecKeyCreateSignature(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
            throw error!.takeRetainedValue()
        }
        return signedData
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
                updateArray.append("KeyPair Retrieved")
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
            updateArray.append("KeyPair Generated")
            storeAndUpdateToKeychain(using: privateKey, tag)
            return (publicKey,privateKey)
        } catch {
            print(error)
            return nil
        }
    }
}

