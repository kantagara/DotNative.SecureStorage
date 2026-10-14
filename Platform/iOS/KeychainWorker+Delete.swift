import Foundation
import Security

extension KeychainWorker {
  func delete(_ namespace: String, key: String) -> KeychainResult {
    remove(query(namespace, key: key))
  }

  func deleteAll(_ namespace: String) -> KeychainResult {
    remove(query(namespace))
  }

  private func remove(_ query: [String: Any]) -> KeychainResult {
    if Task.isCancelled { return .empty }
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound ? .empty : .failure(status)
  }
}
