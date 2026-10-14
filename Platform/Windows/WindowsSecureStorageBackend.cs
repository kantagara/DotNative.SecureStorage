using System.Runtime.InteropServices;
using System.Text;

namespace DotNative.SecureStorage;

internal static class WindowsSecureStorageBackend
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
