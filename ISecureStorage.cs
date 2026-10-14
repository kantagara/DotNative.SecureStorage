namespace DotNative.SecureStorage;

public interface ISecureStorage
{
    Task<string?> ReadAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>A null value deletes the key.</summary>
    Task WriteAsync(string key, string? value, CancellationToken cancellationToken = default);
    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
    Task<bool> ContainsKeyAsync(string key, CancellationToken cancellationToken = default);
    Task<IReadOnlyDictionary<string, string>> ReadAllAsync(
        CancellationToken cancellationToken = default
    );
    Task DeleteAllAsync(CancellationToken cancellationToken = default);
}
