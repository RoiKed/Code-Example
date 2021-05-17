//
//  DecryptionVC.swift
//  PingID
//
//  Created by Roi Kedarya on 15/05/2021.
//

import Foundation
import UIKit
import LocalAuthentication

class DecryptionVC: UIViewController {
    
    var content: UNNotificationContent?
    var delegate: keychainHandler?
    var shouldUseBiometrics: Bool?
    var updateArray = [String]()
    
    @IBOutlet weak var field: UILabel!
    @IBOutlet weak var imageView: UIImageView!
    @IBOutlet weak var updateLabel: UILabel!
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        updateBackgroundImage(with: false)
        if shouldUseBiometrics == true {
            self.authenticationWithTouchID()
        } else {
            handleMessage()
        }
        updateLabel(actions: updateArray)
    }
    
    func updateLabel(actions:[String]) {
        _ = Timer.scheduledTimer(timeInterval: 0.4, target: self, selector: #selector(update(_:)), userInfo: nil, repeats: true)
    }
    
    @objc func update(_ timer: Timer) {
        if updateArray.count > 0 {
            updateLabel.text = updateArray.remove(at: 0)
        } else {
            timer.invalidate()
        }
    }
    
    func handleMessage() {
        do {
            let didHandleMsg = try didHandleMessge()
            updateBackgroundImage(with: didHandleMsg)
        } catch {
            print("Decryption Faild")
        }
    }
    
    private func updateBackgroundImage(with success: Bool) {
        let imageName = success ? "open.jpg": "secure.jpg"
        if let image = UIImage(named: imageName) {
            self.imageView.contentMode = .scaleAspectFill
            self.imageView.image = image
            self.view.backgroundColor = UIColor(patternImage: image)
            self.view.contentMode = .center
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
    
    func didHandleMessge() throws -> Bool {
        var retVal = false
        if let content = content {
            let messageString = content.body
            let signedString = content.subtitle
            if let signedData = signedString.toData(),
               let encryptedMessage = messageString.toData() {
                do {
                    if try isSignatureVerified(signedData as CFData, encryptedMessage as CFData) {
                        do {
                            updateArray.append("Signature Verified")
                            if let decryptedMessage = try decrypt(encryptedMessage as CFData) {
                                updateArray.append("message decrypted")
                                field.text = decryptedMessage
                                retVal = true
                            }
                        } catch {
                            updateArray.append("Decryption Failed")
                            print("Decryption Failed")
                        }
                    }
                } catch {
                    print("signature verification Failed")
                    updateArray.append("signature verification Failed")
                }
            }
        }
        return retVal
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
                    retVal = (error == nil)
                }
            }
        }
        return retVal
    }
}

