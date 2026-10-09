import Foundation
import Security

@MainActor final class SecureStoragePlugin {
  private static var instance: SecureStoragePlugin?
  private let worker = KeychainWorker()

  static func register() {
    if instance == nil { instance = SecureStoragePlugin() }
  }

  private init() {
    let channel = NativeChannels.channel("dotnative.secure-storage")
    for method in ["read", "write", "delete", "readAll", "deleteAll"] {
      channel.handle(method) { [worker] arguments, reply in
        let fields = arguments.fields
        guard let namespace = fields["applicationId"]?.string,
          namespace.range(of: "^[A-Za-z0-9_.-]{1,128}$", options: .regularExpression) != nil,
          namespace != ".", namespace != ".."
        else {
          reply.failure("invalid_argument", "Invalid application identifier")
          return
        }
        let key = fields["key"]?.string
        let value = fields["value"]?.string
        if ["read", "write", "delete"].contains(method) {
          guard let key, !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
            key.utf16.count <= 1024, !key.contains("\0")
          else {
            reply.failure("invalid_argument", "Invalid secure-storage key")
            return
          }
        }
        if method == "write", value == nil || value!.utf16.count > 4 * 1024 * 1024 {
          reply.failure("invalid_argument", "Invalid secure-storage value")
          return
        }
        let task = Task {
          let result = await worker.perform(method, namespace, key, value)
          guard !Task.isCancelled else { return }
          switch result {
          case .empty: reply.success(.null)
          case .text(let value): reply.success(.string(value))
          case .values(let values): reply.success(.map(values.mapValues { .string($0) }))
          case .failure(let status):
            reply.failure(
              "secure_storage_unavailable",
              "Keychain operation failed (OSStatus \(status)). No plaintext fallback was used.")
          }
        }
        reply.onCancel = { task.cancel() }
      }
    }
  }
}

private enum KeychainResult: Sendable {
  case empty
  case text(String)
  case values([String: String])
  case failure(OSStatus)
}

// Serializes Keychain operations away from the renderer UI thread.
private actor KeychainWorker {
  func perform(_ method: String, _ namespace: String, _ key: String?, _ value: String?)
    -> KeychainResult
  {
    if Task.isCancelled { return .empty }
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "dotnative.secure-storage.\(namespace)",
      kSecAttrSynchronizable as String: false,
    ]
    if let key { query[kSecAttrAccount as String] = key }
    var status: OSStatus = errSecSuccess
    switch method {
    case "write":
      guard let value else { return .failure(errSecParam) }
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
    case "delete", "deleteAll":
      status = SecItemDelete(query as CFDictionary)
      if status == errSecItemNotFound { status = errSecSuccess }
    case "read":
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
    case "readAll":
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
    default: return .failure(errSecParam)
    }
    return status == errSecSuccess ? .empty : .failure(status)
  }
}
