import Foundation
import Security

// One actor serializes all operations away from the renderer UI thread.
actor KeychainWorker {
  func query(_ namespace: String, key: String? = nil) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "dotnative.secure-storage.\(namespace)",
      kSecAttrSynchronizable as String: false,
    ]
    if let key { query[kSecAttrAccount as String] = key }
    return query
  }
}

enum KeychainResult: Sendable {
  case empty
  case text(String)
  case values([String: String])
  case failure(OSStatus)

  @MainActor func send(to reply: PluginReply) {
    switch self {
    case .empty: reply.success(.null)
    case .text(let value): reply.success(.string(value))
    case .values(let values): reply.success(.map(values.mapValues { .string($0) }))
    case .failure(let status):
      reply.failure("secure_storage_unavailable",
        "Keychain operation failed (OSStatus \(status)). No plaintext fallback was used.")
    }
  }
}
