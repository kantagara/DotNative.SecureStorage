import Foundation
import Security

extension KeychainWorker {
  func readAll(_ namespace: String) -> KeychainResult {
    if Task.isCancelled { return .empty }
    var query = query(namespace)
    var status: OSStatus = errSecSuccess
    query[kSecReturnData as String] = true
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    var item: CFTypeRef?
    status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return .values([:]) }
    if status == errSecSuccess {
      guard let rows = item as? [[String: Any]] else { return .failure(errSecDecode) }
      var values: [String: String] = [:]
      for row in rows {
        guard let account = row[kSecAttrAccount as String] as? String,
          let data = row[kSecValueData as String] as? Data,
          let value = String(data: data, encoding: .utf8)
        else { return .failure(errSecDecode) }
        values[account] = value
      }
      return .values(values)
    }
    return status == errSecSuccess ? .empty : .failure(status)
  }
}
