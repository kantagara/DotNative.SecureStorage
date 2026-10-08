using DotNative;

namespace DotNative.SecureStorage;

internal static class PlatformGuard
{
    internal static void Desktop(PresentationTarget target)
    {
        if (target.Platform != PresentationTarget.Local.Platform)
            throw new PlatformNotSupportedException(
                "This local service cannot access a remote renderer's OS. Use a native device implementation."
            );
        if (
            target.Platform
            is not (NativePlatform.MacOS or NativePlatform.Windows or NativePlatform.Linux)
        )
            throw new PlatformNotSupportedException(
                "This implementation supports macOS, Windows and Linux. Android/iOS require a native implementation."
            );
    }

    internal static string Namespace(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (
            value.Length > 128
            || value is "." or ".."
            || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_'))
        )
            throw new ArgumentException(
                "Use an application ID of at most 128 ASCII letters, digits, dot, dash or underscore.",
                nameof(value)
            );
        return value;
    }
}
