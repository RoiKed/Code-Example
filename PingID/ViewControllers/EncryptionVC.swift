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
    let codec = EncryptingCodec()
    
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
                let encryptedData = try codec.encrypt(text)
                updateArray.append("String encrypted")
                    do {
                        if  let encryptedData = encryptedData, let signedData = try codec.sign(encryptedData: encryptedData) {
                            updateArray.append("String signed")
                            signedString = signedData.toString()
                            encryptedDataForMsg = encryptedData.toString()
                            clearText() // clear the text only if it was already encrypted
                        }
                    } catch {
                        updateArray.append("Signing Error")
                    }
                
            } catch {
                updateArray.append("Encryption Error")
            }
        } else {
            print("Please enter a message")
        }
        updateActionsLabel()
    }
    
    func updateActionsLabel() {
        _ = Timer.scheduledTimer(timeInterval: 0.3, target: self, selector: #selector(update(_:)), userInfo: nil, repeats: true)
    }
    
    @objc func update(_ timer: Timer) {
        if updateArray.count > 0 {
            updateLabel.text = updateArray.remove(at: 0)
        } else {
            timer.invalidate()
        }
    }
    
    private func clearText() {
        if let text = field.text, !text.isEmpty {
            field.text = nil
        }
    }
    
    
}

