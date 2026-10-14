using System.Runtime.InteropServices;
using System.Text;

namespace DotNative.SecureStorage;

internal static class MacOSSecureStorageBackend
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
