using DotNative.Plugins;

namespace DotNative.SecureStorage;

internal sealed class ChannelSecureStorage : ISecureStorage
{
    private readonly MethodChannel channel;
    private readonly string applicationId;

    public ChannelSecureStorage(IPlatformChannels channels, string applicationId)
    {
        this.applicationId = PlatformGuard.Namespace(applicationId);
        channel = channels.Get("dotnative.secure-storage");
    }

    public async Task<string?> ReadAsync(string key, CancellationToken cancellationToken = default)
    {
        var value = await Invoke("read", key, null, cancellationToken).ConfigureAwait(false);
        return value switch
        {
            null => null,
            string text => text,
            _ => throw new InvalidDataException("Invalid secure-storage response."),
        };
    }

    public async Task WriteAsync(
        string key,
        string? value,
        CancellationToken cancellationToken = default
    )
    {
        if (value is { Length: > 4 * 1024 * 1024 })
            throw new ArgumentOutOfRangeException(nameof(value));
        await Invoke(value is null ? "delete" : "write", key, value, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default) =>
        await Invoke("delete", key, null, cancellationToken).ConfigureAwait(false);

    public async Task<bool> ContainsKeyAsync(
        string key,
        CancellationToken cancellationToken = default
    ) => await ReadAsync(key, cancellationToken).ConfigureAwait(false) is not null;

    public async Task<IReadOnlyDictionary<string, string>> ReadAllAsync(
        CancellationToken cancellationToken = default
    )
    {
        var value = await Invoke("readAll", null, null, cancellationToken).ConfigureAwait(false);
        if (value is not Dictionary<string, object?> fields)
            throw new InvalidDataException("Invalid secure-storage response.");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, item) in fields)
            result.Add(
                key,
                item as string ?? throw new InvalidDataException("Invalid secure-storage value.")
            );
        return result;
    }

    public async Task DeleteAllAsync(CancellationToken cancellationToken = default) =>
        await Invoke("deleteAll", null, null, cancellationToken).ConfigureAwait(false);

    private async Task<object?> Invoke(
        string method,
        string? key,
        string? value,
        CancellationToken token
    )
    {
        if (method is "read" or "write" or "delete")
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key);
            if (key!.Length > 1024 || key.Contains('\0'))
                throw new ArgumentException("Invalid secure-storage key.", nameof(key));
        }
        try
        {
            return await channel
                .InvokeAsync(
                    method,
                    new Dictionary<string, object?>
                    {
                        ["applicationId"] = applicationId,
                        ["key"] = key,
                        ["value"] = value,
                    },
                    token
                )
                .ConfigureAwait(false);
        }
        catch (PluginException error) when (error.Code == "secure_storage_unavailable")
        {
            throw new SecureStorageUnavailableException(error.Message, error);
        }
    }
}
