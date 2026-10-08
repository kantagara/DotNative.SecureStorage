using System.Collections;
using System.Runtime.InteropServices;
using System.Text;
using DotNative.Paths;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

public sealed class SecureStorageUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);

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
        lockPath = Path.Combine(
            new ApplicationPaths(applicationId, target).Get(PathKind.Temporary),
            "secure-storage.lock"
        );
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
            OperatingSystem.IsMacOS() ? Apple.Read(app, key)
            : OperatingSystem.IsWindows() ? Windows.Read(app, key)
            : Linux.Read(app, key);

        internal static void Write(string app, string key, string value)
        {
            if (OperatingSystem.IsMacOS())
                Apple.Write(app, key, value);
            else if (OperatingSystem.IsWindows())
                Windows.Write(app, key, value);
            else
                Linux.Write(app, key, value);
        }

        internal static bool Delete(string app, string key) =>
            OperatingSystem.IsMacOS() ? Apple.Delete(app, key)
            : OperatingSystem.IsWindows() ? Windows.Delete(app, key)
            : Linux.Delete(app, key);

        internal static IReadOnlyDictionary<string, string> ReadAll(string app) =>
            OperatingSystem.IsMacOS() ? Apple.ReadAll(app)
            : OperatingSystem.IsWindows() ? Windows.ReadAll(app)
            : Linux.ReadAll(app);

        internal static void DeleteAll(string app)
        {
            if (OperatingSystem.IsMacOS())
                Apple.DeleteAll(app);
            else if (OperatingSystem.IsWindows())
                Windows.DeleteAll(app);
            else
                Linux.DeleteAll(app);
        }
    }

    private static class Apple
    {
        private const string Cf =
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
        private const string Sec = "/System/Library/Frameworks/Security.framework/Security";
        private static readonly IntPtr cf = NativeLibrary.Load(Cf),
            sec = NativeLibrary.Load(Sec);

        private static IntPtr Constant(string symbol) =>
            Marshal.ReadIntPtr(NativeLibrary.GetExport(sec, symbol));

        private static IntPtr Text(string value)
        {
            var utf8 = Encoding.UTF8.GetBytes(value);
            return CFStringCreateWithBytes(IntPtr.Zero, utf8, (nint)utf8.Length, 0x08000100, false);
        }

        private static IntPtr Dict(params (string Key, IntPtr Value)[] values)
        {
            var keys = new IntPtr[values.Length];
            var vals = new IntPtr[values.Length];
            var allocated = new List<IntPtr>();
            try
            {
                for (var i = 0; i < values.Length; i++)
                {
                    keys[i] = Constant(values[i].Key);
                    vals[i] = values[i].Value;
                }
                return CFDictionaryCreate(
                    IntPtr.Zero,
                    keys,
                    vals,
                    values.Length,
                    NativeLibrary.GetExport(cf, "kCFTypeDictionaryKeyCallBacks"),
                    NativeLibrary.GetExport(cf, "kCFTypeDictionaryValueCallBacks")
                );
            }
            finally
            {
                foreach (var p in allocated)
                    CFRelease(p);
            }
        }

        private static IntPtr StringValue(string s) => Text(s);

        private static IntPtr Base(string app, string? key = null)
        {
            var appRef = StringValue(app);
            var keyRef = key is null ? IntPtr.Zero : StringValue(key);
            try
            {
                return key is null
                    ? Dict(
                        ("kSecClass", Constant("kSecClassGenericPassword")),
                        ("kSecAttrService", appRef)
                    )
                    : Dict(
                        ("kSecClass", Constant("kSecClassGenericPassword")),
                        ("kSecAttrService", appRef),
                        ("kSecAttrAccount", keyRef)
                    );
            }
            finally
            {
                CFRelease(appRef);
                if (keyRef != IntPtr.Zero)
                    CFRelease(keyRef);
            }
        }

        internal static string? Read(string app, string key)
        {
            var q = Base(app, key);
            var query = Merge(
                q,
                ("kSecReturnData", Constant("kCFBooleanTrue")),
                ("kSecMatchLimit", Constant("kSecMatchLimitOne"))
            );
            try
            {
                var status = SecItemCopyMatching(query, out var result);
                if (status == -25300)
                    return null;
                Check(status, "Keychain read");
                try
                {
                    return DecodeData(result);
                }
                finally
                {
                    CFRelease(result);
                }
            }
            finally
            {
                CFRelease(query);
                CFRelease(q);
            }
        }

        internal static void Write(string app, string key, string value)
        {
            var q = Base(app, key);
            var bytes = Encoding.UTF8.GetBytes(value);
            var data = CFDataCreate(IntPtr.Zero, bytes, (nint)bytes.Length);
            var attrs = Dict(("kSecValueData", data));
            try
            {
                var status = SecItemUpdate(q, attrs);
                if (status == -25300)
                {
                    var add = Merge(q, ("kSecValueData", data));
                    try
                    {
                        status = SecItemAdd(add, IntPtr.Zero);
                        if (status == -25299)
                            status = SecItemUpdate(q, attrs);
                        Check(status, "Keychain write");
                    }
                    finally
                    {
                        CFRelease(add);
                    }
                }
                else
                    Check(status, "Keychain update");
            }
            finally
            {
                CFRelease(attrs);
                CFRelease(data);
                CFRelease(q);
            }
        }

        internal static bool Delete(string app, string key)
        {
            var q = Base(app, key);
            try
            {
                var status = SecItemDelete(q);
                if (status == -25300)
                    return false;
                Check(status, "Keychain delete");
                return true;
            }
            finally
            {
                CFRelease(q);
            }
        }

        internal static void DeleteAll(string app)
        {
            var q = Base(app);
            try
            {
                var s = SecItemDelete(q);
                if (s != -25300)
                    Check(s, "Keychain delete all");
            }
            finally
            {
                CFRelease(q);
            }
        }

        internal static IReadOnlyDictionary<string, string> ReadAll(string app)
        {
            var baseQuery = Base(app);
            var q = Merge(
                baseQuery,
                ("kSecReturnAttributes", Constant("kCFBooleanTrue")),
                ("kSecMatchLimit", Constant("kSecMatchLimitAll"))
            );
            try
            {
                var status = SecItemCopyMatching(q, out var result);
                if (status == -25300)
                    return new Dictionary<string, string>();
                Check(status, "Keychain enumerate");
                try
                {
                    var count = CFArrayGetCount(result);
                    var output = new Dictionary<string, string>(StringComparer.Ordinal);
                    for (nint i = 0; i < count; i++)
                    {
                        var item = CFArrayGetValueAtIndex(result, i);
                        var k = CFDictionaryGetValue(item, Constant("kSecAttrAccount"));
                        if (k != IntPtr.Zero)
                        {
                            var key = CFString(k);
                            var value = Read(app, key);
                            if (value is not null)
                                output.Add(key, value);
                        }
                    }
                    return output;
                }
                finally
                {
                    CFRelease(result);
                }
            }
            finally
            {
                CFRelease(q);
                CFRelease(baseQuery);
            }
        }

        private static IntPtr Merge(IntPtr source, params (string Key, IntPtr Value)[] pairs)
        {
            var q = CFDictionaryCreateMutableCopy(IntPtr.Zero, 0, source);
            foreach (var (k, v) in pairs)
                CFDictionarySetValue(q, Constant(k), v);
            return q;
        }

        private static string CFString(IntPtr p)
        {
            var len = CFStringGetLength(p);
            var cap = CFStringGetMaximumSizeForEncoding(len, 0x08000100) + 1;
            var b = new byte[(int)cap];
            if (!CFStringGetCString(p, b, cap, 0x08000100))
                throw new InvalidDataException("Keychain returned invalid UTF-8 key.");
            var end = Array.IndexOf(b, (byte)0);
            return Encoding.UTF8.GetString(b, 0, end < 0 ? b.Length : end);
        }

        private static string DecodeData(IntPtr p)
        {
            var len = CFDataGetLength(p);
            var b = new byte[(int)len];
            Marshal.Copy(CFDataGetBytePtr(p), b, 0, b.Length);
            return new UTF8Encoding(false, true).GetString(b);
        }

        private static void Check(int s, string op)
        {
            if (s != 0)
                throw new SecureStorageUnavailableException(
                    $"{op} failed with Security.framework status {s}; secret was not stored."
                );
        }

        [DllImport(Cf)]
        private static extern IntPtr CFStringCreateWithBytes(
            IntPtr a,
            byte[] b,
            nint n,
            uint e,
            [MarshalAs(UnmanagedType.I1)] bool ext
        );

        [DllImport(Cf)]
        private static extern IntPtr CFDictionaryCreate(
            IntPtr a,
            IntPtr[] k,
            IntPtr[] v,
            nint n,
            IntPtr kc,
            IntPtr vc
        );

        [DllImport(Cf)]
        private static extern IntPtr CFDictionaryCreateMutableCopy(IntPtr a, nint n, IntPtr d);

        [DllImport(Cf)]
        private static extern void CFDictionarySetValue(IntPtr d, IntPtr k, IntPtr v);

        [DllImport(Cf)]
        private static extern IntPtr CFDictionaryGetValue(IntPtr d, IntPtr k);

        [DllImport(Cf)]
        private static extern nint CFArrayGetCount(IntPtr a);

        [DllImport(Cf)]
        private static extern IntPtr CFArrayGetValueAtIndex(IntPtr a, nint i);

        [DllImport(Cf)]
        private static extern nint CFStringGetLength(IntPtr s);

        [DllImport(Cf)]
        private static extern nint CFStringGetMaximumSizeForEncoding(nint n, uint e);

        [DllImport(Cf)]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool CFStringGetCString(IntPtr s, byte[] b, nint n, uint e);

        [DllImport(Cf)]
        private static extern nint CFDataGetLength(IntPtr d);

        [DllImport(Cf)]
        private static extern IntPtr CFDataGetBytePtr(IntPtr d);

        [DllImport(Cf)]
        private static extern IntPtr CFDataCreate(IntPtr a, byte[] b, nint n);

        [DllImport(Cf)]
        private static extern void CFRelease(IntPtr p);

        [DllImport(Sec)]
        private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

        [DllImport(Sec)]
        private static extern int SecItemAdd(IntPtr attributes, IntPtr result);

        [DllImport(Sec)]
        private static extern int SecItemUpdate(IntPtr query, IntPtr attributes);

        [DllImport(Sec)]
        private static extern int SecItemDelete(IntPtr query);
    }

    private static class Windows
    {
        private const string Prefix = "DotNative/";

        [StructLayout(LayoutKind.Sequential)]
        private struct Credential
        {
            public uint Flags,
                Type;
            public IntPtr TargetName,
                Comment;
            public long LastWritten;
            public uint BlobSize;
            public IntPtr Blob;
            public uint Persist,
                AttributeCount;
            public IntPtr Attributes,
                TargetAlias,
                UserName;
        }

        internal static string? Read(string app, string key)
        {
            if (!CredReadW(Prefix + app + "/" + key, 1, 0, out var ptr))
            {
                if (Marshal.GetLastWin32Error() == 1168)
                    return null;
                Throw("Credential Manager read");
            }
            try
            {
                return Decode(Marshal.PtrToStructure<Credential>(ptr));
            }
            finally
            {
                CredFree(ptr);
            }
        }

        internal static void Write(string app, string key, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            if (bytes.Length > 2560)
                throw new ArgumentException(
                    "Windows Credential Manager limits a secret to 2560 UTF-8 bytes."
                );
            var blob = Marshal.AllocHGlobal(Math.Max(bytes.Length, 1));
            var name = Marshal.StringToHGlobalUni(Prefix + app + "/" + key);
            var user = Marshal.StringToHGlobalUni(app);
            try
            {
                Marshal.Copy(bytes, 0, blob, bytes.Length);
                var c = new Credential
                {
                    Type = 1,
                    TargetName = name,
                    BlobSize = (uint)bytes.Length,
                    Blob = blob,
                    Persist = 2,
                    UserName = user,
                };
                if (!CredWriteW(ref c, 0))
                    Throw("Credential Manager write");
            }
            finally
            {
                Marshal.FreeHGlobal(user);
                Marshal.FreeHGlobal(name);
                Marshal.FreeHGlobal(blob);
                Array.Clear(bytes);
            }
        }

        internal static bool Delete(string app, string key)
        {
            if (CredDeleteW(Prefix + app + "/" + key, 1, 0))
                return true;
            if (Marshal.GetLastWin32Error() == 1168)
                return false;
            Throw("Credential Manager delete");
            return false;
        }

        internal static void DeleteAll(string app)
        {
            foreach (var k in ReadAll(app).Keys)
                Delete(app, k);
        }

        internal static IReadOnlyDictionary<string, string> ReadAll(string app)
        {
            if (!CredEnumerateW(null, 0, out var count, out var list))
            {
                if (Marshal.GetLastWin32Error() == 1168)
                    return new Dictionary<string, string>();
                Throw("Credential Manager enumerate");
            }
            try
            {
                var output = new Dictionary<string, string>(StringComparer.Ordinal);
                var prefix = Prefix + app + "/";
                for (uint i = 0; i < count; i++)
                {
                    var p = Marshal.ReadIntPtr(list, checked((int)i * IntPtr.Size));
                    var c = Marshal.PtrToStructure<Credential>(p);
                    var target = Marshal.PtrToStringUni(c.TargetName);
                    if (target is not null && target.StartsWith(prefix, StringComparison.Ordinal))
                        output.Add(target[prefix.Length..], Decode(c));
                }
                return output;
            }
            finally
            {
                CredFree(list);
            }
        }

        private static string Decode(Credential c)
        {
            var b = new byte[c.BlobSize];
            if (b.Length > 0)
                Marshal.Copy(c.Blob, b, 0, b.Length);
            try
            {
                return new UTF8Encoding(false, true).GetString(b);
            }
            finally
            {
                Array.Clear(b);
            }
        }

        private static void Throw(string op) =>
            throw new SecureStorageUnavailableException(
                $"{op} failed with Windows error {Marshal.GetLastWin32Error()}; secret was not stored."
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWriteW(ref Credential c, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredReadW(
            string target,
            uint type,
            uint flags,
            out IntPtr credential
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDeleteW(string target, uint type, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerateW(
            string? filter,
            uint flags,
            out uint count,
            out IntPtr credentials
        );

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);
    }

    private static class Linux
    {
        private const string Lib = "libsecret-1.so.0",
            Glib = "libglib-2.0.so.0",
            Gobject = "libgobject-2.0.so.0";

        [StructLayout(LayoutKind.Sequential)]
        private struct Attribute
        {
            public IntPtr Name;
            public int Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Schema
        {
            public IntPtr Name;
            public uint Flags;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Attribute[] Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GList
        {
            public IntPtr Data,
                Next,
                Previous;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GError
        {
            public uint Domain;
            public int Code;
            public IntPtr Message;
        }

        private static Schema MakeSchema() =>
            new()
            {
                Name = Marshal.StringToHGlobalAnsi("org.dotnative.SecureStorage"),
                Flags = 0,
                Attributes = BuildAttributes(),
            };

        private static Attribute[] BuildAttributes()
        {
            var a = new Attribute[32];
            a[0] = new() { Name = Marshal.StringToHGlobalAnsi("application"), Type = 0 };
            a[1] = new() { Name = Marshal.StringToHGlobalAnsi("key"), Type = 0 };
            return a;
        }

        internal static string? Read(string app, string key)
        {
            var attrs = Map(app, key);
            var schema = UnsafeSchema;
            try
            {
                var ptr = secret_password_lookupv_sync(ref schema, attrs, IntPtr.Zero, out var err);
                Check(err, "Secret Service read");
                if (ptr == IntPtr.Zero)
                    return null;
                try
                {
                    return Marshal.PtrToStringUTF8(ptr) ?? "";
                }
                finally
                {
                    g_free(ptr);
                }
            }
            finally
            {
                g_hash_table_unref(attrs);
            }
        }

        internal static void Write(string app, string key, string value)
        {
            var attrs = Map(app, key);
            var pass = Utf8(value);
            try
            {
                var schema = UnsafeSchema;
                if (
                    !secret_password_storev_sync(
                        ref schema,
                        attrs,
                        "default",
                        "DotNative secret",
                        pass,
                        IntPtr.Zero,
                        out var err
                    )
                )
                    Check(err, "Secret Service write");
            }
            finally
            {
                g_free(pass);
                g_hash_table_unref(attrs);
            }
        }

        internal static bool Delete(string app, string key)
        {
            var attrs = Map(app, key);
            var schema = UnsafeSchema;
            try
            {
                var ok = secret_password_clearv_sync(ref schema, attrs, IntPtr.Zero, out var err);
                Check(err, "Secret Service delete");
                if (
                    !ok
                    && secret_password_lookupv_sync(ref schema, attrs, IntPtr.Zero, out err)
                        is var remaining
                    && remaining != IntPtr.Zero
                )
                {
                    g_free(remaining);
                    throw new SecureStorageUnavailableException(
                        "Secret Service could not delete the matching secret; no unencrypted fallback was used."
                    );
                }
                Check(err, "Secret Service delete verification");
                return ok;
            }
            finally
            {
                g_hash_table_unref(attrs);
            }
        }

        internal static void DeleteAll(string app)
        {
            foreach (var key in ReadAll(app).Keys)
                Delete(app, key);
        }

        internal static IReadOnlyDictionary<string, string> ReadAll(string app)
        {
            var attrs = Map(app, null);
            var schema = UnsafeSchema;
            try
            {
                var list = secret_password_searchv_sync(
                    ref schema,
                    attrs,
                    2 | 4 | 8,
                    IntPtr.Zero,
                    out var err
                );
                Check(err, "Secret Service enumerate");
                var output = new Dictionary<string, string>(StringComparer.Ordinal);
                try
                {
                    for (var node = list; node != IntPtr.Zero; )
                    {
                        var item = Marshal.PtrToStructure<GList>(node);
                        var itemAttrs = secret_item_get_attributes(item.Data);
                        var keyName = Utf8("key");
                        var key = g_hash_table_lookup(itemAttrs, keyName);
                        g_free(keyName);
                        var secret = secret_item_get_secret(item.Data);
                        if (key != IntPtr.Zero && secret != IntPtr.Zero)
                        {
                            var secretPtr = secret_value_get(secret, out var length);
                            var bytes = new byte[length];
                            Marshal.Copy(secretPtr, bytes, 0, bytes.Length);
                            output.Add(
                                Marshal.PtrToStringUTF8(key) ?? "",
                                new UTF8Encoding(false, true).GetString(bytes)
                            );
                            Array.Clear(bytes);
                        }
                        if (secret != IntPtr.Zero)
                            secret_value_unref(secret);
                        if (itemAttrs != IntPtr.Zero)
                            g_hash_table_unref(itemAttrs);
                        node = item.Next;
                    }
                    return output;
                }
                finally
                {
                    if (list != IntPtr.Zero)
                        g_list_free_full(
                            list,
                            NativeLibrary.GetExport(NativeLibrary.Load(Gobject), "g_object_unref")
                        );
                }
            }
            finally
            {
                g_hash_table_unref(attrs);
            }
        }

        private static readonly Schema SharedSchema = MakeSchema();
        private static Schema UnsafeSchema => SharedSchema;

        private static IntPtr Map(string app, string? key)
        {
            var glib = NativeLibrary.Load(Glib);
            var table = g_hash_table_new_full(
                NativeLibrary.GetExport(glib, "g_str_hash"),
                NativeLibrary.GetExport(glib, "g_str_equal"),
                NativeLibrary.GetExport(glib, "g_free"),
                NativeLibrary.GetExport(glib, "g_free")
            );
            void Put(string name, string value)
            {
                g_hash_table_insert(table, Utf8(name), Utf8(value));
            }
            Put("application", app);
            if (key is not null)
                Put("key", key);
            return table;
        }

        private static IntPtr Utf8(string s) => g_strdup(s);

        private static void Check(IntPtr e, string op)
        {
            if (e == IntPtr.Zero)
                return;
            var error = Marshal.PtrToStructure<GError>(e);
            var msg = Marshal.PtrToStringUTF8(error.Message) ?? "unknown Secret Service error";
            g_error_free(e);
            throw new SecureStorageUnavailableException(
                $"{op} failed: {msg}. No unencrypted fallback was used."
            );
        }

        [DllImport(Glib)]
        private static extern IntPtr g_strdup([MarshalAs(UnmanagedType.LPUTF8Str)] string s);

        [DllImport(Glib)]
        private static extern void g_free(IntPtr p);

        [DllImport(Glib)]
        private static extern IntPtr g_hash_table_new_full(
            IntPtr hash,
            IntPtr equal,
            IntPtr keyDestroy,
            IntPtr valueDestroy
        );

        [DllImport(Glib)]
        private static extern void g_hash_table_insert(IntPtr table, IntPtr key, IntPtr value);

        [DllImport(Glib)]
        private static extern IntPtr g_hash_table_lookup(IntPtr table, IntPtr key);

        [DllImport(Glib)]
        private static extern void g_hash_table_unref(IntPtr table);

        [DllImport(Glib)]
        private static extern void g_list_free_full(IntPtr list, IntPtr freeFunc);

        [DllImport(Glib)]
        private static extern void g_error_free(IntPtr error);

        [DllImport(Gobject)]
        private static extern void g_object_unref(IntPtr obj);

        [DllImport(Lib)]
        private static extern IntPtr secret_password_lookupv_sync(
            ref Schema schema,
            IntPtr attributes,
            IntPtr cancellable,
            out IntPtr error
        );

        [DllImport(Lib)]
        private static extern bool secret_password_storev_sync(
            ref Schema schema,
            IntPtr attributes,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string collection,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string label,
            IntPtr password,
            IntPtr cancellable,
            out IntPtr error
        );

        [DllImport(Lib)]
        private static extern bool secret_password_clearv_sync(
            ref Schema schema,
            IntPtr attributes,
            IntPtr cancellable,
            out IntPtr error
        );

        [DllImport(Lib)]
        private static extern IntPtr secret_password_searchv_sync(
            ref Schema schema,
            IntPtr attributes,
            uint flags,
            IntPtr cancellable,
            out IntPtr error
        );

        [DllImport(Lib)]
        private static extern IntPtr secret_item_get_attributes(IntPtr item);

        [DllImport(Lib)]
        private static extern IntPtr secret_item_get_secret(IntPtr item);

        [DllImport(Lib)]
        private static extern IntPtr secret_value_get(IntPtr value, out nuint length);

        [DllImport(Lib)]
        private static extern void secret_value_unref(IntPtr value);
    }
}

public static class SecureStorageServices
{
    public static IServiceCollection AddSecureStorage(
        this IServiceCollection services,
        string applicationId
    )
    {
        services.TryAddSingleton<ISecureStorage>(p => new SystemSecureStorage(
            applicationId,
            p.GetService<PresentationTarget>()
        ));
        return services;
    }
}
