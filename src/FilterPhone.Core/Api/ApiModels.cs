using System.Text.Json;
using FilterPhone.Core.Trust;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Api;

/// <summary>Result of <c>POST /v1/enroll</c> or <c>POST /v1/transfer</c> (server: Services.enroll / transfer_enroll).</summary>
public sealed record EnrollmentResult(
    int DeviceId,
    string Token,
    string Status,
    int Level,
    string LevelName,
    VpnSettings Vpn,
    string VpnJson,
    CaInfo Ca)
{
    public override string ToString() =>
        $"EnrollmentResult(device={DeviceId}, status={Status}, level={Level}, token=<redacted>)";
}

/// <summary><c>GET /v1/device/vpn</c> and <c>POST /v1/device/rekey</c>: VPN settings plus the filtering CA.</summary>
public sealed record VpnBundle(VpnSettings Vpn, string VpnJson, CaInfo? Ca);

/// <summary>Subset of <c>GET /v1/device</c> (Services.device_status) that the desktop client uses.</summary>
public sealed record DeviceInfo(
    int DeviceId,
    string Name,
    string Status,
    int Level,
    string LevelName,
    string Message,
    bool? ViaVpn,
    string? VpnIp,
    int HeartbeatIntervalSeconds,
    string SupportWhatsApp,
    long ServerTime)
{
    public bool IsActive => Status == "active";
}

/// <summary><c>POST /v1/device/heartbeat</c> response (Services.heartbeat).</summary>
public sealed record HeartbeatResult(string Status, int? PolicyVersion, int IntervalSeconds, string Message);

/// <summary>
/// What the desktop client reports in a heartbeat. Only fields the server keeps
/// (server/filterphone/api/service.py: sanitize_heartbeat) are sent; there is no personal content.
/// </summary>
public sealed record HeartbeatReport
{
    public required string AppVersion { get; init; }
    public required string DeviceUid { get; init; }
    public int? PolicyVersion { get; init; }
    public bool? CaInstalled { get; init; }
    public required string VpnState { get; init; }          // "UP" / "DOWN"
    public int? HandshakeAgeSeconds { get; init; }
    public bool? TunnelAutoStart { get; init; }              // reported as vpn.always_on
    public bool? KillSwitchActive { get; init; }             // reported as vpn.lockdown
    public int Reconnects { get; init; }
    public string? VpnError { get; init; }
    public bool? DataOk { get; init; }
    public string? DataError { get; init; }
    public int DataFails { get; init; }
    public int? DataFailAgeSeconds { get; init; }

    internal Dictionary<string, object?> ToJsonBody()
    {
        var vpn = new Dictionary<string, object?> { ["state"] = VpnState, ["reconnects"] = Reconnects, ["data_fails"] = DataFails };
        AddIf(vpn, "handshake_age_s", HandshakeAgeSeconds);
        AddIf(vpn, "always_on", TunnelAutoStart);
        AddIf(vpn, "lockdown", KillSwitchActive);
        AddIf(vpn, "error", Truncate(VpnError));
        AddIf(vpn, "data_ok", DataOk);
        AddIf(vpn, "data_error", Truncate(DataError));
        AddIf(vpn, "data_fail_age_s", DataFailAgeSeconds);
        var body = new Dictionary<string, object?>
        {
            ["app_version"] = AppVersion,
            ["device_uid"] = DeviceUid,
            ["ts"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["vpn"] = vpn,
        };
        AddIf(body, "policy_version", PolicyVersion);
        AddIf(body, "ca_installed", CaInstalled);
        return body;
    }

    private static string? Truncate(string? s) => s is null ? null : s.Length <= 80 ? s : s[..80];

    private static void AddIf(Dictionary<string, object?> d, string key, object? value)
    {
        if (value is not null)
        {
            d[key] = value;
        }
    }
}

internal static class Json
{
    public static string String(JsonElement o, string name, string fallback = "") =>
        o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? fallback : fallback;

    public static int Int(JsonElement o, string name, int fallback = 0) =>
        o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var v) ? v : fallback;

    public static int? NullableInt(JsonElement o, string name) =>
        o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var v) ? v : null;

    public static long Long(JsonElement o, string name) =>
        o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt64(out var v) ? v : 0;

    public static bool? Bool(JsonElement o, string name) =>
        o.TryGetProperty(name, out var e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False ? e.GetBoolean() : null;
}
