//
//  KeychainManager.swift
//  PingID
//
//  Created by Roi Kedarya on 25/05/2021.
//

import Foundation
 
class KeychainManager: keychainHandler {
    
    func storeAndUpdateToKeychain(using key: SecKey,_ tag: String) -> String {
        var retVal = ""
        let tagData = tag.data(using: .utf8)!
        let query = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tagData,
                                       kSecValueRef as String: key] as CFDictionary
        let status: OSStatus
        if isExistInKeychain(query) {
            let attributesToUpdate = [kSecValueRef as String: key] as CFDictionary
            status = SecItemUpdate(query, attributesToUpdate)
            retVal = "Key was Updated in Keychain"
            //updateArray.append("Key was Updated in Keychain")
        } else {
            status = SecItemAdd(query, nil)
            retVal = " Key added to Keychain "
            //updateArray.append(" Key added to Keychain ")
        }
        guard status == errSecSuccess else {
            retVal = " Error adding key to KeyChain "
            //updateArray.append(" Error adding key to KeyChain ")
            return retVal
        }
        return retVal
    }
    
    func deleteFromKeychain(query: CFDictionary) throws -> Bool {
        var retVal = false
        if isExistInKeychain(query) {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw  cryptoError.itemNotFoundInKeychain
            }
            retVal = true
        }
        return retVal
    }
    
    /*
     deleteAllKeys - deletes all the keys stored in the keychain
     if any of the keys can't be deleted, it will go on to the next key and will try to delete it
     returns true - only if all the keys deleted succesfuly otherwise returns false
     */
    func deleteAllKeys() -> Bool {
        var retVal = true
        let actions = [Query.encrypt.rawValue,Query.sign.rawValue]
        for action in actions {
            do {
                let query = getQuery(for: action)
                retVal = try deleteFromKeychain(query: query) && retVal
            } catch {
                retVal = false
            }
        }
        return retVal
    }
    
    func getKey(for query: CFDictionary) -> SecKey? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        if status == errSecSuccess, let item = item {
            //updateArray.append(" Key taken from Keychain")
            return (item as! SecKey)
        } else {
            return nil
        }
    }
    
    func isExistInKeychain(_ query: CFDictionary) -> Bool {
        let status = SecItemCopyMatching(query, nil)
        return status == errSecSuccess
    }
    
    /*
     If the keyPair exist in the key chain  - return the keyPair,
     otherwise, genrate a new pair that will be stored in the key chain
     */
     func getKeyPair(for tag: String) -> (publicKey: SecKey, privateKey: SecKey)? {
        let query = [kSecClass as String: kSecClassKey,
                     kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                     kSecReturnRef as String: true,
                     kSecAttrApplicationTag as String: tag.data(using: .utf8)!] as CFDictionary
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query, &item)
        if status == errSecSuccess {
            let privateKey = item as! SecKey
            if let publicKey = SecKeyCopyPublicKey(privateKey) {
                //updateArray.append("KeyPair Retrieved")
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
            //updateArray.append("KeyPair Generated")
            storeAndUpdateToKeychain(using: privateKey, tag)
            return (publicKey,privateKey)
        } catch {
            print(error)
            return nil
        }
    }
    
    func getQuery(for tag: String) -> CFDictionary {
        let query = [
            kSecClass as String: kSecClassKey,
            kSecReturnRef as String: true,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!
        ] as CFDictionary
        return query
    }
    
    func isSignatureVerified(_ signature: CFData, _ encryptedMsg: CFData) throws -> Bool {
        var retVal = false
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        let query = getQuery(for: Query.sign.rawValue)
        if let privateKey = getKey(for: query) {
            guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
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
        return retVal
    }
}
