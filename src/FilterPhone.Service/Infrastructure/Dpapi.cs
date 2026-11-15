using System.Runtime.InteropServices;
using FilterPhone.Service.Native;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// DPAPI in the security context of the service account (LocalSystem): only SYSTEM can decrypt.
/// The optional description is what WireGuard for Windows checks for *.conf.dpapi files
/// (conf/dpapi/dpapi_windows.go: CryptProtectData(bytes, name)).
/// </summary>
internal static unsafe class Dpapi
{
    public static byte[] Protect(ReadOnlySpan<byte> data, string? description, ReadOnlySpan<byte> entropy = default)
    {
        fixed (byte* pData = data)
        fixed (byte* pEntropy = entropy)
        {
            var input = new DATA_BLOB { cbData = (uint)data.Length, pbData = (IntPtr)pData };
            var ent = new DATA_BLOB { cbData = (uint)entropy.Length, pbData = (IntPtr)pEntropy };
            DATA_BLOB output = default;
            if (!Win32.CryptProtectData(&input, description, entropy.IsEmpty ? null : &ent, IntPtr.Zero, IntPtr.Zero,
                    Win32.CRYPTPROTECT_UI_FORBIDDEN, &output))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "CryptProtectData failed");
            }
            try
            {
                return new ReadOnlySpan<byte>((void*)output.pbData, (int)output.cbData).ToArray();
            }
            finally
            {
                Win32.LocalFree(output.pbData);
            }
        }
    }

    public static byte[] Unprotect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy = default)
    {
        fixed (byte* pData = data)
        fixed (byte* pEntropy = entropy)
        {
            var input = new DATA_BLOB { cbData = (uint)data.Length, pbData = (IntPtr)pData };
            var ent = new DATA_BLOB { cbData = (uint)entropy.Length, pbData = (IntPtr)pEntropy };
            DATA_BLOB output = default;
            IntPtr desc = IntPtr.Zero;
            if (!Win32.CryptUnprotectData(&input, &desc, entropy.IsEmpty ? null : &ent, IntPtr.Zero, IntPtr.Zero,
                    Win32.CRYPTPROTECT_UI_FORBIDDEN, &output))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "CryptUnprotectData failed");
            }
            try
            {
                var result = new ReadOnlySpan<byte>((void*)output.pbData, (int)output.cbData).ToArray();
                new Span<byte>((void*)output.pbData, (int)output.cbData).Clear();
                return result;
            }
            finally
            {
                Win32.LocalFree(output.pbData);
                if (desc != IntPtr.Zero)
                {
                    Win32.LocalFree(desc);
                }
            }
        }
    }
}
