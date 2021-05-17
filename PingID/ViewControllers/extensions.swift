//
//  extensions.swift
//  PingID
//
//  Created by Roi Kedarya on 16/05/2021.
//

import Foundation
import UIKit

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
        UNUserNotificationCenter.current().add(request) { (error) in
            if let error = error {
              print("error adding notification request - \(error)")
            }
        }
    }

    func addObserverForAppInBackground() {
        let notificationCenter = NotificationCenter.default
            notificationCenter.addObserver(self, selector: #selector(appMovedToBackground), name: UIApplication.willResignActiveNotification, object: nil)
    }
    
    @objc func appMovedToBackground() {
        if let signatureForMsg = signatureForMsg, let encryptedDataForMsg = encryptedDataForMsg {
            createNotification(with: signatureForMsg, encryptedMessage: encryptedDataForMsg)

            self.signatureForMsg = nil
            self.encryptedDataForMsg = nil
        }
    }
}

extension EncryptionVC: UNUserNotificationCenterDelegate {
    
    private func handleSegue(content: UNNotificationContent) {
        if let navigationController = self.navigationController {
            decryptionViewController.content = content
            decryptionViewController.delegate = self
            decryptionViewController.sig = self.sig
            decryptionViewController.encryptedmsg = self.encryptedmsg
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
        var result: String
        if isExistInKeychain(query) {
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
    
    func deleteFromKeychain(key: SecKey) throws {
        guard let query = key as? [String : Any] else { return }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw  cryptoError.itemNotFoundInKeychain
        }
    }
    
    func getKey(for query: CFDictionary) -> SecKey? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        if status == errSecSuccess, let item = item {
            return (item as! SecKey)
        }else {
            return nil
        }
    }
    
    func isExistInKeychain(_ query: CFDictionary) -> Bool {
        let status = SecItemCopyMatching(query, nil)
        return status == errSecSuccess
    }
}
