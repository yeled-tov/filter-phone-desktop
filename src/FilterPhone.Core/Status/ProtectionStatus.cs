using System.Text.Json.Serialization;

namespace FilterPhone.Core.Status;

[JsonConverter(typeof(JsonStringEnumConverter<CheckState>))]
public enum CheckState
{
    Unknown,
    Pending,
    Ok,
    Failed,
    Unsupported,
}

/// <summary>The independent protection layers. Each one is verified separately; none implies another.</summary>
public static class Layers
{
    public const string Enrollment = "enrollment";
    public const string Tunnel = "tunnel";               // tunnel service running + fresh WireGuard handshake
    public const string ServerPath = "server_path";      // server sees our API calls from the tunnel IP + traffic flows
    public const string KillSwitch = "kill_switch";      // fail-closed WFP filters installed
    public const string CaTrust = "ca_trust";            // filtering CA in LocalMachine\Root
    public const string Interception = "interception";   // HTTPS from the internet is presented by the filtering proxy
    public const string ImagePath = "image_path";        // an image request is handled by the filtering proxy
    public const string ChromeOnly = "chrome_only";      // other browsers blocked by Windows application control
    public const string ChromePolicy = "chrome_policy";  // Chrome machine policies (QUIC, DoH, proxy) applied
    public const string StoreBlock = "store_block";      // Microsoft Store app blocked (optional, chosen at install)

    public static readonly string[] All =
        [Enrollment, Tunnel, ServerPath, KillSwitch, CaTrust, Interception, ImagePath, ChromeOnly, ChromePolicy, StoreBlock];
}

public sealed record LayerCheck(string Layer, CheckState State, string Code, DateTimeOffset? CheckedAt)
{
    public static LayerCheck Unknown(string layer) => new(layer, CheckState.Unknown, "not_checked", null);
}

[JsonConverter(typeof(JsonStringEnumConverter<OverallState>))]
public enum OverallState
{
    NotEnrolled,
    AwaitingApproval,       // registration sent; waiting for the administrator (usually after payment)
    RegistrationRejected,
    SetupIncomplete,
    Connecting,
    Reconnecting,
    ServerUnavailable,
    FilteringTestFailed,
    AdminActionRequired,
    DeviceInactive,
    ProtectedWithLimitations,
    Protected,
}

/// <summary>Everything the UI needs to show. Contains no secrets (no token, key, code or CA private data).</summary>
public sealed record ProtectionSnapshot
{
    public required OverallState Overall { get; init; }
    public required IReadOnlyDictionary<string, LayerCheck> Checks { get; init; }
    public int? DeviceId { get; init; }
    public string? DeviceName { get; init; }
    public string? LevelName { get; init; }
    public string? ServerStatus { get; init; }
    public string? ServerMessage { get; init; }
    public string? TunnelAddress { get; init; }
    public DateTimeOffset? LastHandshake { get; init; }
    public DateTimeOffset? LastVerified { get; init; }
    public DateTimeOffset? ProtectedSince { get; init; }
    public string Version { get; init; } = ProductConfig.Version;
    public string WindowsEdition { get; init; } = string.Empty;
    public string WindowsBuild { get; init; } = string.Empty;
    public string SupportWhatsApp { get; init; } = string.Empty;
    public bool SupportEmailConfigured { get; init; }
    public RegistrationInfo? Registration { get; init; }
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// A registration waiting for (or refused by) the administrator, as the customer sent it — shown on the
/// "waiting for approval" screen. Contains no secret.
/// </summary>
public sealed record RegistrationInfo
{
    public required string Status { get; init; }        // "pending" / "rejected"
    public string Message { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Phone { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public int Level { get; init; }
    public IReadOnlyList<string> Options { get; init; } = [];
    public string Note { get; init; } = string.Empty;
    public DateTimeOffset SubmittedAt { get; init; }
    public DateTimeOffset? LastChecked { get; init; }
}
