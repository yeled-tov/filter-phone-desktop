using System.Text;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// Device secrets: the API token, the WireGuard private key and the server VPN settings.
/// Each is encrypted with DPAPI under LocalSystem (only SYSTEM can decrypt) with product-specific entropy,
/// and stored in a folder that only SYSTEM and Administrators can read. Nothing here is ever logged.
/// </summary>
internal static class SecretStore
{
    public const string Token = "device-token";
    public const string PrivateKey = "wg-private-key";
    public const string VpnJson = "vpn-settings";
    public const string CaPem = "filtering-ca";

    private static readonly byte[] Entropy = "FilterPhone.Desktop.SecretStore.v1"u8.ToArray();

    public static void Put(string name, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            SecureDirectory.WriteAllBytesAtomic(PathOf(name), Dpapi.Protect(bytes, null, Entropy));
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    public static string? Get(string name)
    {
        var path = PathOf(name);
        if (!File.Exists(path))
        {
            return null;
        }
        try
        {
            var plain = Dpapi.Unprotect(File.ReadAllBytes(path), Entropy);
            try
            {
                return Encoding.UTF8.GetString(plain);
            }
            finally
            {
                Array.Clear(plain);
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;    // undecryptable (e.g. copied from another machine): treated as missing
        }
    }

    public static void Delete(string name)
    {
        var path = PathOf(name);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    public static void DeleteAll()
    {
        foreach (var n in new[] { Token, PrivateKey, VpnJson, CaPem })
        {
            Delete(n);
        }
    }

    private static string PathOf(string name) => Path.Combine(Paths.Secrets, name + ".bin");
}
