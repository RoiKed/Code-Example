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
    var shouldUseBiometrics: Bool?
    var updateArray = [String]()
    let codec = EncryptingCodec()
    
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
    }
    
    func deleteKeys()  -> Bool{
        return KeychainManager().deleteAllKeys()
    }
    
    func updateActionsLabel() {
        _ = Timer.scheduledTimer(timeInterval: 0.6, target: self, selector: #selector(update(_:)), userInfo: nil, repeats: true)
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
            let message = deleteKeys() ? " All Keys have been deleted " : " Faild to delete some of the keys "
            updateArray.append(message)
            updateActionsLabel()
        } catch {
            updateArray.append("Decryption Faild")
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
    
    func didHandleMessge() throws -> Bool {
        var retVal = false
        if let content = content {
            let messageString = content.body
            let signedString = content.subtitle
            if let signedData = signedString.toData(),
               let encryptedMessage = messageString.toData() {
                do {
                    if try codec.isSignatureVerified(signedData as CFData, encryptedMessage as CFData) {
                        do {
                            updateArray.append("Signature Verified")
                            if let decryptedMessage = try codec.decrypt(encryptedMessage as CFData) {
                                updateArray.append("message decrypted")
                                field.text = decryptedMessage
                                retVal = true
                            }
                        } catch {
                            updateArray.append("Decryption Failed")
                        }
                    }
                } catch {
                    updateArray.append("signature verification Failed")
                }
            }
        }
        return retVal
    }
    
}

