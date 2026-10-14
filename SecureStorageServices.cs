using DotNative.Plugins;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DotNative.SecureStorage;

public static class SecureStorageServices
{
    public static IServiceCollection AddSecureStorage(this IServiceCollection services) =>
        services.AddSecureStorageCore(null);

    public static IServiceCollection AddSecureStorage(
        this IServiceCollection services,
        string applicationId
    ) => services.AddSecureStorageCore(applicationId);

    private static IServiceCollection AddSecureStorageCore(
        this IServiceCollection services,
        string? applicationId
    )
    {
        services.TryAddSingleton<ISecureStorage>(provider =>
        {
            var target = provider.GetService<PresentationTarget>() ?? PresentationTarget.Local;
            return SecureStorage.Create(
                provider.GetService<IPlatformChannels>(),
                target,
                applicationId
            );
        });
        return services;
    }
}
