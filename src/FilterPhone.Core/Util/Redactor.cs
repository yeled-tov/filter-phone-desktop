using System.Text.RegularExpressions;

namespace FilterPhone.Core.Util;

/// <summary>
/// Removes secrets and personal data from text before it is logged or exported. Applied to every log line
/// and to the whole diagnostic report, as a second line of defence: code paths never log secrets on purpose.
/// </summary>
public static partial class Redactor
{
    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }
        var s = PemBlock().Replace(text, "<pem-redacted>");
        s = WgKeyLine().Replace(s, "$1<redacted>");
        s = Bearer().Replace(s, "Bearer <redacted>");
        s = WgKey().Replace(s, "<key-redacted>");
        s = TransferCode().Replace(s, "<code-redacted>");
        s = ActivationCode().Replace(s, "<code-redacted>");
        s = LongToken().Replace(s, "<secret-redacted>");
        s = Email().Replace(s, "<email-redacted>");
        s = Phone().Replace(s, "<phone-redacted>");
        s = UserProfile().Replace(s, "$1<user>");
        return s;
    }

    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(-----END [A-Z0-9 ]+-----|$)")]
    private static partial Regex PemBlock();

    [GeneratedRegex(@"(?im)^(\s*(?:PrivateKey|PresharedKey)\s*=\s*).*$")]
    private static partial Regex WgKeyLine();

    [GeneratedRegex(@"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")]
    private static partial Regex Bearer();

    // 32 bytes in base64 (WireGuard keys and preshared keys).
    [GeneratedRegex(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=")]
    private static partial Regex WgKey();

    [GeneratedRegex(@"(?i)\bFPT-[A-Za-z0-9_-]+")]
    private static partial Regex TransferCode();

    // Activation codes: XXXXX-XXXXX from an unambiguous alphabet (server: security.new_code).
    [GeneratedRegex(@"\b[A-HJ-NP-Z2-9]{5}-?[A-HJ-NP-Z2-9]{5}\b")]
    private static partial Regex ActivationCode();

    // Device tokens are secrets.token_urlsafe(32) (43 chars); also catches other long opaque secrets.
    [GeneratedRegex(@"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")]
    private static partial Regex LongToken();

    [GeneratedRegex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")]
    private static partial Regex Email();

    [GeneratedRegex(@"(?<!\d)(?:\+?972|0)5\d[- ]?\d{3}[- ]?\d{4}(?!\d)")]
    private static partial Regex Phone();

    [GeneratedRegex(@"(?i)([A-Z]:\\Users\\)[^\\\s""']+")]
    private static partial Regex UserProfile();
}
