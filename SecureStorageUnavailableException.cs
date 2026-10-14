namespace DotNative.SecureStorage;

public sealed class SecureStorageUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);
