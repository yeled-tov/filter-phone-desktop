using System.Text;
using FilterPhone.Core.Status;

namespace FilterPhone.Core.Support;

/// <summary>
/// Builds the prepared support message and the links that open WhatsApp or the mail client. The message
/// only ever contains the device number, app version and protection state: never the activation code,
/// token, keys, VPN configuration or browsing data. The user edits it before anything is sent.
/// </summary>
public static class SupportMessage
{
    public const int MaxMessageLength = 1500;

    public static string Compose(ProtectionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var lines = new List<string> { "שלום, אני צריך עזרה ב-FilterPhone למחשב (Windows)." };
        if (snapshot.DeviceId is int id)
        {
            lines.Add(snapshot.DeviceName is { Length: > 0 } name ? $"מכשיר #{id} · {name}" : $"מכשיר #{id}");
        }
        lines.Add($"גרסה: {snapshot.Version}");
        lines.Add($"מצב: {StateText.Hebrew(snapshot.Overall)}");
        return string.Join('\n', lines);
    }

    /// <summary>whatsapp:// link handled by WhatsApp Desktop (registered URI protocol).</summary>
    public static Uri WhatsAppDesktopUri(string number, string message) =>
        new($"whatsapp://send?phone={CheckNumber(number)}&text={Encode(message)}");

    /// <summary>wa.me link opened in the browser when WhatsApp Desktop is not installed.</summary>
    public static Uri WhatsAppWebUri(string number, string message) =>
        new($"https://wa.me/{CheckNumber(number)}?text={Encode(message)}");

    public static Uri MailtoUri(string email, string subject, string body)
    {
        if (string.IsNullOrWhiteSpace(email) || email.IndexOfAny(['?', '&', '\r', '\n', ' ']) >= 0 || !email.Contains('@', StringComparison.Ordinal))
        {
            throw new ArgumentException("A verified support e-mail address is required.", nameof(email));
        }
        return new Uri($"mailto:{email}?subject={Encode(subject)}&body={Encode(body)}");
    }

    private static string CheckNumber(string number)
    {
        if (number.Length is < 8 or > 15 || !number.All(char.IsAsciiDigit))
        {
            throw new ArgumentException("Support WhatsApp number must be digits in international format.", nameof(number));
        }
        return number;
    }

    private static string Encode(string text)
    {
        var clean = new StringBuilder(text.Length);
        foreach (var ch in text.Length > MaxMessageLength ? text[..MaxMessageLength] : text)
        {
            if (ch == '\n' || !char.IsControl(ch))
            {
                clean.Append(ch);
            }
        }
        return Uri.EscapeDataString(clean.ToString());
    }
}

/// <summary>Short Hebrew names for the overall states (shared by the UI and support messages).</summary>
public static class StateText
{
    public static string Hebrew(OverallState state) => state switch
    {
        OverallState.Protected => "ההגנה פעילה ומאומתת",
        OverallState.ProtectedWithLimitations => "ההגנה פעילה, עם מגבלות במחשב הזה",
        OverallState.Connecting => "מתחבר ומאמת",
        OverallState.Reconnecting => "מתחבר מחדש",
        OverallState.ServerUnavailable => "השרת לא זמין",
        OverallState.FilteringTestFailed => "בדיקת הסינון נכשלה",
        OverallState.SetupIncomplete => "ההתקנה לא הושלמה",
        OverallState.AdminActionRequired => "נדרשת פעולת מנהל",
        OverallState.DeviceInactive => "המכשיר לא פעיל בשרת",
        OverallState.NotEnrolled => "לא הופעל",
        _ => "לא ידוע",
    };
}
