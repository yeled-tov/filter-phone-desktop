using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace FilterPhone.Core.Vpn;

/// <summary>A device key pair. The private key never leaves the machine and is never logged.</summary>
public sealed class WireGuardKeyPair : IDisposable
{
    private readonly byte[] _private;

    internal WireGuardKeyPair(byte[] privateKey, string publicKey)
    {
        _private = privateKey;
        PublicKey = publicKey;
    }

    public string PublicKey { get; }

    /// <summary>Base64 private key, only for writing the protected tunnel configuration.</summary>
    public string PrivateKeyBase64() => Convert.ToBase64String(_private);

    public void Dispose() => CryptographicOperations.ZeroMemory(_private);

    public override string ToString() => $"WireGuardKeyPair(public={PublicKey}, private=<redacted>)";
}

/// <summary>Curve25519 keys exactly as <c>wg genkey</c> / <c>wg pubkey</c> produce them.</summary>
public static partial class WireGuardKeys
{
    public const int KeyLength = 32;

    /// <summary>Same rule as the server (server/filterphone/api/security.py: is_wg_key).</summary>
    [GeneratedRegex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")]
    private static partial Regex KeyPattern();

    public static bool IsValidKey(string? key) => key is not null && KeyPattern().IsMatch(key);

    public static WireGuardKeyPair Generate()
    {
        var priv = new byte[KeyLength];
        RandomNumberGenerator.Fill(priv);
        Clamp(priv);
        return new WireGuardKeyPair(priv, PublicFromPrivate(priv));
    }

    public static WireGuardKeyPair FromPrivateKey(string privateKeyBase64)
    {
        if (!IsValidKey(privateKeyBase64))
        {
            throw new FormatException("Invalid WireGuard private key format.");
        }
        var priv = Convert.FromBase64String(privateKeyBase64);
        return new WireGuardKeyPair(priv, PublicFromPrivate(priv));
    }

    internal static string PublicFromPrivate(byte[] priv)
    {
        if (priv.Length != KeyLength)
        {
            throw new ArgumentException("A WireGuard key is 32 bytes.", nameof(priv));
        }
        var pub = new byte[KeyLength];
        // X25519.ScalarMultBase clamps internally, matching wg(8).
        X25519.ScalarMultBase(priv, 0, pub, 0);
        return Convert.ToBase64String(pub);
    }

    internal static void Clamp(byte[] k)
    {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }
}
