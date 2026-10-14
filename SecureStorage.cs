using System.Reflection;
using DotNative.Plugins;

namespace DotNative.SecureStorage;

/// <summary>Creates storage for the supplied application target. No service registration is required.</summary>
public static class SecureStorage
{
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
