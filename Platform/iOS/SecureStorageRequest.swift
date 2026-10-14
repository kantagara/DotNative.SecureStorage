import Foundation

struct SecureStorageRequest {
  let namespace: String
  private let fields: [String: PluginValue]

  init(_ arguments: PluginValue) throws {
    fields = arguments.fields
    let provided = fields["applicationId"]?.string
    guard let namespace = (provided?.isEmpty == false ? provided : nil) ?? Bundle.main.bundleIdentifier,
      namespace.range(of: "^[A-Za-z0-9_.-]{1,128}$", options: .regularExpression) != nil,
      namespace != ".", namespace != ".."
    else { throw InvalidArgument("Invalid application identifier") }
    self.namespace = namespace
  }

  func requiredKey() throws -> String {
    guard let key = fields["key"]?.string,
      !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      key.utf16.count <= 1024, !key.contains("\0")
    else { throw InvalidArgument("Invalid secure-storage key") }
    return key
  }

  func requiredValue() throws -> String {
    guard let value = fields["value"]?.string, value.utf16.count <= 4 * 1024 * 1024
    else { throw InvalidArgument("Invalid secure-storage value") }
    return value
  }

  private struct InvalidArgument: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
  }
}
