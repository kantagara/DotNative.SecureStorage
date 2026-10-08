using System;
using Microsoft.Extensions.DependencyInjection;

namespace DotNative.SecureStorage;

public static class SecureStorageServiceProviderExtensions
{
#if NET10_0_OR_GREATER
    extension(IServiceProvider services)
    {
        /// <summary>Resolves the registered plugin using the provider's DI lifetime.</summary>
        public ISecureStorage SecureStorage => services.GetRequiredService<ISecureStorage>();
    }
#else
    /// <summary>Resolves the registered plugin using the provider's DI lifetime.</summary>
    public static ISecureStorage SecureStorage(this IServiceProvider services) =>
        services.GetRequiredService<ISecureStorage>();
#endif
}
