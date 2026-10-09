# DotNative.SecureStorage

Secure storage for Android, iOS, macOS, Windows and Linux through one C# API.

| Platform | Backend |
| --- | --- |
| Android (API 30+ app baseline) | Preferences DataStore containing a Tink AES-256-GCM encrypted map; encrypted Tink keyset wrapped by Android Keystore |
| iOS (16+) | Native Keychain generic-password items |
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service through libsecret |

There is no plaintext fallback. Android encrypts both key names and values as one
payload, binds ciphertext to the application namespace, and stores DataStore and
the encrypted keyset under `noBackupFilesDir`. The Keystore master key is
non-exportable. Missing/corrupt key material fails; it never resets existing secrets.
Android storage is intended for a single application process; multiple processes
sharing a namespace are not supported by this Preferences DataStore backend.
iOS uses `AfterFirstUnlockThisDeviceOnly`, disables iCloud synchronization and
scopes every operation by service/application ID. Keychain entries can survive
an uninstall; Android entries do not. No cross-library data migration is provided.

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

## Native build integration

Register `AddSecureStorage(applicationId)` once. DI selects native channels for
an Android/iOS presentation target, including a desktop development host driving
a mobile renderer, and the existing local OS backend for desktop.

Native source and Android dependency declarations ship inside the NuGet package.
The current DotNative CLI stages `Platform/Android/dependencies.gradle`; the app
publish pipeline uses the `DotNativeAndroidGradle` MSBuild item. Both paths include
DataStore 1.2.1, Tink Android 1.23.0 and coroutines Android 1.10.2 automatically.
Use a framework/CLI build containing this dependency integration; an older
preview CLI does not stage these dependencies. Source development can use a
`ProjectReference`; for the app publish path, import this plugin's
`buildTransitive/DotNative.SecureStorage.targets` when using a source reference
(NuGet imports it automatically). iOS links the Security framework. Native channels currently limit each encoded
request/reply to 1 MiB, including `ReadAllAsync` results. Cancellation prevents
queued operations when possible; an OS write already in progress may complete.

## Development and verification

Reference this project from a small DotNative app, register the service, and call
write/read/delete from its UI on the target OS. For persistence, write a test
value, fully stop the app, launch it again, read it, and delete it. Exercise
missing keys, empty strings, read-all, delete-all, cancellation, namespace
isolation and unavailable protected storage as well.

C# builds for net9.0/net10.0 and native compilation are distinct from runtime
verification. Desktop runtime evidence is described above. The new Android/iOS
backends need device/simulator runtime verification; compilation alone does not
establish Keystore/Keychain persistence or device behavior.

The package does not depend on DotNative.Paths: desktop lock files use the same
OS temporary-directory/application-ID location directly. This prevents a
desktop-only Paths plugin from being discovered during mobile preview.
