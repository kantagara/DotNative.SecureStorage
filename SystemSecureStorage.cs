namespace DotNative.SecureStorage;

/// <summary>OS credential storage only. Throws if its protected store cannot be reached.</summary>
public sealed class SystemSecureStorage : ISecureStorage
{
    private readonly string applicationId;

    private readonly string lockPath;

    private static readonly SemaphoreSlim ProcessGate = new(1, 1);

    public SystemSecureStorage(string applicationId, PresentationTarget? target = null)
    {
        PlatformGuard.Desktop(target ?? PresentationTarget.Local);
        this.applicationId = PlatformGuard.Namespace(applicationId);
        var directory = Path.Combine(Path.GetTempPath(), this.applicationId);
        if (!Path.IsPathFullyQualified(directory))
            throw new DirectoryNotFoundException(
                "The OS did not provide an absolute temporary directory."
            );
        Directory.CreateDirectory(directory);
        lockPath = Path.Combine(directory, "secure-storage.lock");
    }

    public Task<string?> ReadAsync(string key, CancellationToken cancellationToken = default)
    {
        ValidateKey(key);
        return Execute(() => Native.Read(applicationId, key), cancellationToken);
    }

    public Task WriteAsync(string key, string? value, CancellationToken cancellationToken = default)
    {
        ValidateKey(key);
        if (value?.Contains('\0') == true)
            throw new ArgumentException(
                "Secret cannot contain NUL on the Linux Secret Service API.",
                nameof(value)
            );
        if (value is { Length: > 4 * 1024 * 1024 })
            throw new ArgumentException("Secret exceeds 4 MiB.", nameof(value));
        return Execute(
            () =>
            {
                if (value is null)
                    Native.Delete(applicationId, key);
                else
                    Native.Write(applicationId, key, value);
                return 0;
            },
            cancellationToken
        );
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        ValidateKey(key);
        return Execute(() => Native.Delete(applicationId, key), cancellationToken);
    }

    public async Task<bool> ContainsKeyAsync(
        string key,
        CancellationToken cancellationToken = default
    ) => await ReadAsync(key, cancellationToken).ConfigureAwait(false) is not null;

    public Task<IReadOnlyDictionary<string, string>> ReadAllAsync(
        CancellationToken cancellationToken = default
    )
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Execute<IReadOnlyDictionary<string, string>>(
            () => Native.ReadAll(applicationId),
            cancellationToken
        );
    }

    public Task DeleteAllAsync(CancellationToken cancellationToken = default)
    {
        return Execute(
            () =>
            {
                Native.DeleteAll(applicationId);
                return true;
            },
            cancellationToken
        );
    }

    private async Task<T> Execute<T>(Func<T> call, CancellationToken token)
    {
        await ProcessGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            FileStream held;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    held = new FileStream(
                        lockPath,
                        FileMode.OpenOrCreate,
                        FileAccess.ReadWrite,
                        FileShare.None
                    );
                    break;
                }
                catch (IOException e) when ((e.HResult & 0xffff) is 11 or 32 or 33 or 35)
                {
                    await Task.Delay(25, token).ConfigureAwait(false);
                }
            }
            using (held)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    return await Task.Run(call, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception error) when (IsUnavailableNative(error))
                {
                    throw new SecureStorageUnavailableException(
                        "The operating system's protected credential store is unavailable. No plaintext fallback was used.",
                        error
                    );
                }
            }
        }
        finally
        {
            ProcessGate.Release();
        }
    }

    private static bool IsUnavailableNative(Exception error) =>
        error switch
        {
            DllNotFoundException or EntryPointNotFoundException => true,
            TypeInitializationException { InnerException: not null } init => IsUnavailableNative(
                init.InnerException!
            ),
            _ => false,
        };

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        if (key.Length > 1024 || key.Any(char.IsControl))
            throw new ArgumentException(
                "Key must contain at most 1024 non-control characters.",
                nameof(key)
            );
    }

    private static class Native
    {
        internal static string? Read(string app, string key) =>
            OperatingSystem.IsMacOS() ? MacOSSecureStorageBackend.Read(app, key)
            : OperatingSystem.IsWindows() ? WindowsSecureStorageBackend.Read(app, key)
            : LinuxSecureStorageBackend.Read(app, key);

        internal static void Write(string app, string key, string value)
        {
            if (OperatingSystem.IsMacOS())
                MacOSSecureStorageBackend.Write(app, key, value);
            else if (OperatingSystem.IsWindows())
                WindowsSecureStorageBackend.Write(app, key, value);
            else
                LinuxSecureStorageBackend.Write(app, key, value);
        }

        internal static bool Delete(string app, string key) =>
            OperatingSystem.IsMacOS() ? MacOSSecureStorageBackend.Delete(app, key)
            : OperatingSystem.IsWindows() ? WindowsSecureStorageBackend.Delete(app, key)
            : LinuxSecureStorageBackend.Delete(app, key);

        internal static IReadOnlyDictionary<string, string> ReadAll(string app) =>
            OperatingSystem.IsMacOS() ? MacOSSecureStorageBackend.ReadAll(app)
            : OperatingSystem.IsWindows() ? WindowsSecureStorageBackend.ReadAll(app)
            : LinuxSecureStorageBackend.ReadAll(app);

        internal static void DeleteAll(string app)
        {
            if (OperatingSystem.IsMacOS())
                MacOSSecureStorageBackend.DeleteAll(app);
            else if (OperatingSystem.IsWindows())
                WindowsSecureStorageBackend.DeleteAll(app);
            else
                LinuxSecureStorageBackend.DeleteAll(app);
        }
    }
}
