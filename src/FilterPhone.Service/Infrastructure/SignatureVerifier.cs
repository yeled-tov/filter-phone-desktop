using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using FilterPhone.Service.Native;

namespace FilterPhone.Service.Infrastructure;

/// <summary>Authenticode verification (WinVerifyTrust) plus an expected publisher check.</summary>
internal static unsafe class SignatureVerifier
{
    public const string WireGuardPublisher = "WireGuard LLC";

    private static readonly Dictionary<string, (DateTime Modified, long Size, bool Ok, string Reason)> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Cached by path, size and modification time, so a replaced binary is always re-verified.</summary>
    public static bool IsTrusted(string path, string expectedOrganization, out string reason)
    {
        if (!File.Exists(path))
        {
            reason = "missing";
            return false;
        }
        var fi = new FileInfo(path);
        var key = path + "\0" + expectedOrganization;
        lock (Cache)
        {
            if (Cache.TryGetValue(key, out var c) && c.Modified == fi.LastWriteTimeUtc && c.Size == fi.Length)
            {
                reason = c.Reason;
                return c.Ok;
            }
        }
        var ok = Verify(path, expectedOrganization, out reason);
        lock (Cache)
        {
            Cache[key] = (fi.LastWriteTimeUtc, fi.Length, ok, reason);
        }
        return ok;
    }

    private static bool Verify(string path, string expectedOrganization, out string reason)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = (uint)sizeof(WINTRUST_FILE_INFO), pcwszFilePath = pathPtr };
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE (offline-safe; the publisher check still applies)
                dwUnionChoice = 1,           // WTD_CHOICE_FILE
                pFile = (IntPtr)(&file),
                dwStateAction = 1,           // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x00000080,    // WTD_REVOCATION_CHECK_NONE
            };
            var action = Win32.WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var result = Win32.WinVerifyTrust(new IntPtr(-1), &action, &data);
            data.dwStateAction = 2;          // WTD_STATEACTION_CLOSE
            _ = Win32.WinVerifyTrust(new IntPtr(-1), &action, &data);
            if (result != 0)
            {
                reason = $"untrusted_signature_0x{result:x8}";
                return false;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
        }

        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the supported way to read the Authenticode signer.
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var org = signer.GetNameInfo(X509NameType.SimpleName, false);
            var subject = signer.Subject;
            if (!subject.Contains($"O={expectedOrganization}", StringComparison.Ordinal) && org != expectedOrganization)
            {
                reason = "unexpected_publisher";
                return false;
            }
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            reason = "no_signer";
            return false;
        }
        reason = "ok";
        return true;
    }
}
