using System.Reflection;
using DotNative.Plugins;

namespace DotNative.SecureStorage;

/// <summary>Creates storage for the supplied application target. No service registration is required.</summary>
public static class SecureStorage
{
    /// <summary>Creates storage for the current DotNative runtime. No plugin DI registration is required.</summary>
    public static ISecureStorage Create()
    {
        var context = PluginRuntime.Current;
        return Create(context.Channels, context.Target);
    }

    public static Task<string?> ReadAsync(string key, CancellationToken cancellationToken = default) =>
        Create().ReadAsync(key, cancellationToken);

    public static Task WriteAsync(string key, string? value, CancellationToken cancellationToken = default) =>
        Create().WriteAsync(key, value, cancellationToken);

    public static Task DeleteAsync(string key, CancellationToken cancellationToken = default) =>
        Create().DeleteAsync(key, cancellationToken);

    public static Task<bool> ContainsKeyAsync(string key, CancellationToken cancellationToken = default) =>
        Create().ContainsKeyAsync(key, cancellationToken);

    public static Task<IReadOnlyDictionary<string, string>> ReadAllAsync(CancellationToken cancellationToken = default) =>
        Create().ReadAllAsync(cancellationToken);

    public static Task DeleteAllAsync(CancellationToken cancellationToken = default) =>
        Create().DeleteAllAsync(cancellationToken);

    public static ISecureStorage Create(
        IPlatformChannels? channels,
        PresentationTarget target,
        string? applicationId = null
    )
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Platform is NativePlatform.IOS or NativePlatform.Android
            ? new ChannelSecureStorage(
                channels ?? throw new ArgumentNullException(nameof(channels)),
                applicationId
            )
            : new SystemSecureStorage(applicationId ?? DesktopName(), target);
    }

    private static string DesktopName()
    {
        var name = Assembly.GetEntryAssembly()?.GetName().Name;
        if (string.IsNullOrWhiteSpace(name))
            throw new InvalidOperationException(
                "Desktop secure storage needs an application name. Pass it to SecureStorage.Create."
            );
        return name;
    }
}
