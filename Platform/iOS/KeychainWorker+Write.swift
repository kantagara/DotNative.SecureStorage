import Foundation
import Security

extension KeychainWorker {
  func write(_ namespace: String, key: String, value: String) -> KeychainResult {
    if Task.isCancelled { return .empty }
    var query = query(namespace, key: key)
    var status: OSStatus = errSecSuccess
    let updates: [String: Any] = [
      kSecValueData as String: Data(value.utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    status = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
    if status == errSecItemNotFound {
      query.merge(updates) { _, new in new }
      status = SecItemAdd(query as CFDictionary, nil)
      // Another process may have created the item between update and add.
      if status == errSecDuplicateItem {
        query.removeValue(forKey: kSecValueData as String)
        query.removeValue(forKey: kSecAttrAccessible as String)
        status = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
      }
    }
    return status == errSecSuccess ? .empty : .failure(status)
  }
}
