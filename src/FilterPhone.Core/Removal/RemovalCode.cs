using System.Security.Cryptography;
using System.Text;

namespace FilterPhone.Core.Removal;

/// <summary>
/// Removal codes: removing FilterPhone from a PC needs a code the administrator issues in the dashboard for
/// that PC. The PC checks the code itself, also without internet (browsing is blocked while protection is
/// incomplete). Same algorithm as the server (yeled-tov/filterphone: server/filterphone/api/removal.py):
///   mac  = HMAC-SHA256(key, "filterphone-removal:{deviceId}:{day}")   day = Unix seconds / 86400 (UTC)
///   code = the top 50 bits of mac as 10 Crockford base32 characters, shown as XXXXX-XXXXX.
/// A code for day D is accepted on days D-1, D and D+1 (clock skew), so it is valid for 24 to 48 hours.
/// </summary>
public static class RemovalCode
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const long DaySeconds = 86_400;

    /// <summary>True when <paramref name="keyBase64"/> is a well-formed 32-byte key.</summary>
    public static bool IsValidKey(string? keyBase64)
    {
        if (string.IsNullOrEmpty(keyBase64) || keyBase64.Length != 44)
        {
            return false;
        }
        var buffer = new byte[33];
        return Convert.TryFromBase64String(keyBase64, buffer, out var written) && written == 32;
    }

    public static long DayOf(DateTimeOffset t) => t.ToUnixTimeSeconds() / DaySeconds;

    public static string Compute(string keyBase64, int deviceId, long day)
    {
        if (!IsValidKey(keyBase64))
        {
            throw new ArgumentException("The removal key is invalid.", nameof(keyBase64));
        }
        var key = Convert.FromBase64String(keyBase64);
        try
        {
            var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(
                string.Create(System.Globalization.CultureInfo.InvariantCulture, $"filterphone-removal:{deviceId}:{day}")));
            ulong n = 0;
            for (var i = 0; i < 7; i++)
            {
                n = (n << 8) | mac[i];
            }
            n >>= 6;                                  // the top 50 bits
            Span<char> chars = stackalloc char[10];
            for (var i = 9; i >= 0; i--)
            {
                chars[i] = Alphabet[(int)(n & 31)];
                n >>= 5;
            }
            return string.Concat(chars[..5], "-", chars[5..]);
        }
        finally
        {
            Array.Clear(key);
        }
    }

    /// <summary>Upper-cases, drops spaces and dashes, and maps look-alike letters (O→0, I/L→1).</summary>
    public static string Normalize(string? code)
    {
        if (string.IsNullOrEmpty(code) || code.Length > 40)
        {
            return string.Empty;
        }
        var sb = new StringBuilder(10);
        foreach (var raw in code)
        {
            if (!char.IsAsciiLetterOrDigit(raw))
            {
                continue;
            }
            var c = char.ToUpperInvariant(raw);
            sb.Append(c switch { 'O' => '0', 'I' or 'L' => '1', _ => c });
        }
        var s = sb.ToString();
        return s.Length == 10 ? string.Concat(s.AsSpan(0, 5), "-", s.AsSpan(5)) : string.Empty;
    }

    public static bool Verify(string? keyBase64, int deviceId, string? code, DateTimeOffset now)
    {
        var given = Normalize(code);
        if (given.Length == 0 || !IsValidKey(keyBase64))
        {
            return false;
        }
        var today = DayOf(now);
        var ok = false;
        foreach (var day in new[] { today - 1, today, today + 1 })
        {
            // Constant-time comparison, and every candidate is checked.
            ok |= CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(given), Encoding.ASCII.GetBytes(Compute(keyBase64!, deviceId, day)));
        }
        return ok;
    }
}

/// <summary>When removing FilterPhone from this PC needs a removal code.</summary>
public static class RemovalPolicy
{
    /// <summary>How long an accepted removal code authorizes the uninstall.</summary>
    public static readonly TimeSpan AuthorizationLifetime = TimeSpan.FromMinutes(30);

    /// <summary>
    /// A code is required only for an enrolled PC that already holds its removal key, and whose device still
    /// exists on the server. Without a key (an older server, or the PC never reached it) a code could never be
    /// issued, so the PC is not locked in; a PC the administrator deleted can always be removed.
    /// </summary>
    public static bool IsCodeRequired(bool enrolled, bool hasRemovalKey, string? serverStatus) =>
        enrolled && hasRemovalKey && serverStatus != "unauthorized";

    public static bool IsAuthorized(DateTimeOffset? authorizedUntil, DateTimeOffset now) =>
        authorizedUntil is { } until && now < until && until - now <= AuthorizationLifetime;
}
