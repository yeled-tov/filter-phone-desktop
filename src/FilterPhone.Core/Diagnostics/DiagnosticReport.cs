using System.Globalization;
using System.Text;
using FilterPhone.Core.Status;
using FilterPhone.Core.Support;
using FilterPhone.Core.Util;

namespace FilterPhone.Core.Diagnostics;

/// <summary>
/// The privacy-conscious diagnostic export: version, Windows version, per-layer verification results,
/// handshake age and sanitised recent errors. It never includes the token, keys, activation code,
/// VPN configuration, CA material, browsing history or page contents, and the whole text is passed
/// through <see cref="Redactor"/> as a final safeguard.
/// </summary>
public static class DiagnosticReport
{
    public static string Build(ProtectionSnapshot s, IEnumerable<string> recentEvents, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(s);
        ArgumentNullException.ThrowIfNull(recentEvents);
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine("FilterPhone Desktop — diagnostic report");
        sb.AppendLine(inv, $"Generated (UTC): {now.UtcDateTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(inv, $"App version: {s.Version}");
        sb.AppendLine(inv, $"Windows: {s.WindowsEdition} build {s.WindowsBuild}");
        sb.AppendLine(inv, $"Overall state: {s.Overall} ({StateText.Hebrew(s.Overall)})");
        sb.AppendLine(inv, $"Device number: {(s.DeviceId is int id ? id.ToString(inv) : "-")}");
        sb.AppendLine(inv, $"Server status: {s.ServerStatus ?? "-"}");
        sb.AppendLine(inv, $"Last handshake: {Age(s.LastHandshake, now)}");
        sb.AppendLine(inv, $"Last full verification: {Age(s.LastVerified, now)}");
        sb.AppendLine();
        sb.AppendLine("Layer checks:");
        foreach (var layer in Layers.All)
        {
            var c = s.Checks.TryGetValue(layer, out var v) ? v : LayerCheck.Unknown(layer);
            sb.AppendLine(inv, $"  {layer,-14} {c.State,-11} {c.Code,-28} {Age(c.CheckedAt, now)}");
        }
        sb.AppendLine();
        sb.AppendLine("Recent service events (sanitised):");
        foreach (var e in recentEvents.TakeLast(80))
        {
            sb.Append("  ").AppendLine(e.ReplaceLineEndings(" "));
        }
        return Redactor.Redact(sb.ToString());
    }

    private static string Age(DateTimeOffset? t, DateTimeOffset now)
    {
        if (t is null)
        {
            return "never";
        }
        var age = now - t.Value;
        return age.TotalSeconds < 0 ? "just now"
            : age.TotalMinutes < 2 ? $"{(int)age.TotalSeconds}s ago"
            : age.TotalHours < 2 ? $"{(int)age.TotalMinutes}m ago"
            : $"{(int)age.TotalHours}h ago";
    }
}
