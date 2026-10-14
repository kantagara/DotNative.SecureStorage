using System.Runtime.InteropServices;
using System.Text;

namespace DotNative.SecureStorage;

internal static class LinuxSecureStorageBackend
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
