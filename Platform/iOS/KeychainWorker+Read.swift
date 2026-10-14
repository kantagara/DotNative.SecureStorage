import Foundation
import Security

extension KeychainWorker {
  func read(_ namespace: String, key: String) -> KeychainResult {
    if Task.isCancelled { return .empty }
    var query = query(namespace, key: key)
    var status: OSStatus = errSecSuccess
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return .empty }
    if status == errSecSuccess {
      guard let data = item as? Data, let value = String(data: data, encoding: .utf8)
      else { return .failure(errSecDecode) }
      return .text(value)
    }
    return status == errSecSuccess ? .empty : .failure(status)
  }
}
