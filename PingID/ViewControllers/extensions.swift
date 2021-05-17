//
//  extensions.swift
//  PingID
//
//  Created by Roi Kedarya on 16/05/2021.
//

import Foundation
import UIKit
import LocalAuthentication

enum cryptoError: Error {
    case signError
    case encryptError
    case decryptError
    case verificationError
    case unsupportedAlgorithm
    case itemNotFoundInKeychain
}

enum Query: String {
    case sign = "Sign"
    case encrypt = "RSA-Encryption"
}

protocol keychainHandler {
    func deleteFromKeychain(query: CFDictionary) throws
    func storeAndUpdateToKeychain(using key: SecKey,_ tag: String)
    func isExistInKeychain(_ query: CFDictionary) -> Bool
    func getKey(for query: CFDictionary) -> SecKey?
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
        userNotificationCenter.requestAuthorization(options: authOptions) { (success, error) in
            if let error = error {
                print("Error: ", error)
            }
        }
    }
    
    private func createNotification(with signature: String ,encryptedMessage:String) {
        let content = UNMutableNotificationContent()
        let title = "Ping ID"
        
        content.sound = .default
        content.title = title
        content.subtitle = signature
        content.body = encryptedMessage
    
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 15, repeats: false)
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: trigger)
        UNUserNotificationCenter.current().add(request) { [weak self] (error) in
            if let error = error {
              print("error adding notification request - \(error)")
            } else {
                self?.updateArray.append("Timer created for 15 sec")
            }
        }
    }

    func addObserverForAppInBackground() {
        let notificationCenter = NotificationCenter.default
            notificationCenter.addObserver(self, selector: #selector(appMovedToBackground), name: UIApplication.willResignActiveNotification, object: nil)
    }
    
    @objc func appMovedToBackground() {
        if let signedString = signedString, let encryptedDataForMsg = encryptedDataForMsg {
            createNotification(with: signedString, encryptedMessage: encryptedDataForMsg)

            self.signedString = nil
            self.encryptedDataForMsg = nil
        }
    }
}

extension EncryptionVC: UNUserNotificationCenterDelegate {
    
    private func handleSegue(content: UNNotificationContent) {
        if let navigationController = self.navigationController {
            decryptionViewController.content = content
            decryptionViewController.delegate = self
            decryptionViewController.shouldUseBiometrics = switchButton.isOn
            navigationController.pushViewController(decryptionViewController, animated: true)
        }
    }
    
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let content = response.notification.request.content
        handleSegue(content: content)
        completionHandler()
    }
}

extension EncryptionVC: keychainHandler {
    
    func storeAndUpdateToKeychain(using key: SecKey,_ tag: String) {
        let tagData = tag.data(using: .utf8)!
        let query = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tagData,
                                       kSecValueRef as String: key] as CFDictionary
        let status: OSStatus
        if isExistInKeychain(query) {
            let attributesToUpdate = [kSecValueRef as String: key] as CFDictionary
            status = SecItemUpdate(query, attributesToUpdate)
            updateArray.append(" Key was Updated in Keychain")
        } else {
            status = SecItemAdd(query, nil)
            updateArray.append(" Key added to Keychain ")
        }
        guard status == errSecSuccess else {
            updateArray.append(" Error adding key to KeyChain ")
            return
        }
    }
    
    func deleteFromKeychain(query: CFDictionary) throws {
        if isExistInKeychain(query) {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw  cryptoError.itemNotFoundInKeychain
            }
            updateArray.append(" Key Deleted from Keychain")
        }
    }
    
    func getKey(for query: CFDictionary) -> SecKey? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        if status == errSecSuccess, let item = item {
            updateArray.append(" Key taken from Keychain")
            return (item as! SecKey)
        } else {
            return nil
        }
    }
    
    func isExistInKeychain(_ query: CFDictionary) -> Bool {
        let status = SecItemCopyMatching(query, nil)
        return status == errSecSuccess
    }
}

extension DecryptionVC {
    
    func authenticationWithTouchID() {
        let localAuthenticationContext = LAContext()
        localAuthenticationContext.localizedFallbackTitle = "Please use your Passcode"

        var authorizationError: NSError?
        let reason = "Authentication required to access the secure data"
        
        if localAuthenticationContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authorizationError) {
            localAuthenticationContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, evaluateError in
                DispatchQueue.main.async {
                    if success {
                        self?.handleMessage()
                        
                    } else {
                        // Failed to authenticate
                        self?.updateArray.append("Local Authentication failed")
                        self?.deleteKeys()
                        self?.updateActionsLabel()
                        guard let error = evaluateError else {
                            return
                        }
                        print(error)
                    
                    }
                }
            }
        } else {
            
            guard let error = authorizationError else {
                return
            }
            print(error)
        }
    }
}

extension Data
{
    func toString() -> String
    {
        return self.base64EncodedString(options: [])
    }
}

extension String
{
    func toData() -> Data? {
        return Data(base64Encoded: self, options: [])
    }
}
