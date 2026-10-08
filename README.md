# DotNative.SecureStorage

Desktop secrets use OS credential stores: macOS Keychain, Windows Credential Manager, and the freedesktop Secret Service through libsecret on Linux. There is no file or plaintext fallback. Mobile uses the same C# API/package identifier, but this release deliberately throws `PlatformNotSupportedException` there until Android Keystore/Tink and iOS Keychain plugin implementations are integrated.

```csharp
builder.Services.AddSecureStorage("com.example.myapp");
var secure = provider.SecureStorage;
await secure.WriteAsync("refresh-token", token, cancellationToken);
var restored = await secure.ReadAsync("refresh-token", cancellationToken);
```

`WriteAsync(key, null)` deletes; `ReadAsync` returns `null` for a missing key and preserves empty strings. `DeleteAsync` is idempotent. `ContainsKeyAsync`, `ReadAllAsync` and `DeleteAllAsync` use only the app's namespace. Calls are serialized within the process and across same-user app processes. Cancellation before dispatch prevents an operation; Keychain/credential manager/Secret Service calls already in progress finish and report their result.

Linux needs `libsecret-1` and a running Secret Service such as GNOME Keyring or KWallet. If the native library or unlocked secret service is unavailable, the call fails with `SecureStorageUnavailableException`. macOS secrets are generic-password Keychain items keyed by app ID/account. Windows stores UTF-8 credentials in Credential Manager with user-profile persistence; one value is limited to 2560 bytes. Linux Secret Service labels and attributes may be visible to the session's keyring UI. Errors retain OS status; no protected-store failure is converted into a successful write.

The API provides CRUD operations, nullable write/delete semantics and read-all enumeration. This package does not migrate records from other libraries, and its native formats are not compatible with other storage libraries. App identifier and service configuration must match between app instances that share these values.

Build locally: `dotnet build -p:DotNativeSourceRoot=../dotNative`. macOS Keychain, Windows Credential Manager, and Linux Secret Service (GNOME Keyring on Debian 12 ARM64) passed CRUD, enumeration, deletion, and separate-process persistence checks. Linux requires an unlocked Secret Service and never falls back to plaintext.

## Service access

Import `DotNative.SecureStorage` to access the plugin through `IServiceProvider`:

```csharp
using DotNative.SecureStorage;

var plugin = services.SecureStorage;
```

The getter calls `GetRequiredService<ISecureStorage>()` on every access, preserving
DI lifetimes and the usual missing-registration error. Register the plugin with
`AddSecureStorage(...)` before building the provider.

A `net10.0` application uses the property syntax with C# 14 or later. A
`net9.0` application uses only the method equivalent:

```csharp
var plugin = services.SecureStorage();
```

The package contains separate `net9.0` and `net10.0` assemblies. NuGet selects
the assembly matching the application target framework. `NET10_0_OR_GREATER`
selects the property; the `#else` branch selects the method.

Build and pack both targets with .NET 10 SDK. A source build using .NET 9 SDK
builds only `net9.0`; it does not produce the .NET 10 assembly.
