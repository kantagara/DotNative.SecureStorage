import Foundation

@MainActor final class SecureStoragePlugin {
  private static var instance: SecureStoragePlugin?
  private let worker = KeychainWorker()

  static func register() {
    if instance == nil { instance = SecureStoragePlugin() }
  }

  private init() {
    let worker = self.worker
    handle("read") { request in
      await worker.read(request.namespace, key: try request.requiredKey())
    }
    handle("write") { request in
      await worker.write(request.namespace, key: try request.requiredKey(),
                         value: try request.requiredValue())
    }
    handle("delete") { request in
      await worker.delete(request.namespace, key: try request.requiredKey())
    }
    handle("readAll") { request in
      await worker.readAll(request.namespace)
    }
    handle("deleteAll") { request in
      await worker.deleteAll(request.namespace)
    }
  }

  private func handle(
    _ method: String,
    operation: @escaping @MainActor (SecureStorageRequest) async throws -> KeychainResult
  ) {
    NativeChannels.channel("dotnative.secure-storage").handle(method) { arguments, reply in
      let task = Task {
        do {
          let request = try SecureStorageRequest(arguments)
          let result = try await operation(request)
          guard !Task.isCancelled else { return }
          result.send(to: reply)
        } catch {
          guard !Task.isCancelled else { return }
          reply.failure("invalid_argument", error.localizedDescription)
        }
      }
      reply.onCancel = { task.cancel() }
    }
  }
}
