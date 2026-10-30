using System.Text.Json;
using System.Text.Json.Serialization;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// Non-secret persistent state (state.json in the protected data folder). Secrets (token, private key,
/// VPN settings) are kept separately in <see cref="SecretStore"/>.
/// </summary>
internal sealed class MachineState
{
    public bool Enrolled { get; set; }
    public int? DeviceId { get; set; }
    public string? DeviceName { get; set; }
    public string? LevelName { get; set; }
    public string DeviceUid { get; set; } = string.Empty;
    public string? TunnelAddress { get; set; }
    public string? VpnFingerprint { get; set; }
    public string? ServerStatus { get; set; }
    public string? ServerMessage { get; set; }
    public int? PolicyVersion { get; set; }
    public int HeartbeatIntervalSeconds { get; set; } = 900;
    public string SupportWhatsApp { get; set; } = string.Empty;

    /// <summary>Last resolved addresses, used while DNS outside the tunnel is blocked by the kill switch.</summary>
    public List<string> EndpointAddresses { get; set; } = [];
    public List<string> ApiAddresses { get; set; } = [];

    /// <summary>The kill switch is enabled after the tunnel has been verified once, then kept on permanently.</summary>
    public bool NetworkLockEnabled { get; set; }
    public bool TunnelEverVerified { get; set; }
    public DateTimeOffset? ProtectedSince { get; set; }

    /// <summary>Thumbprints (SHA-1, as used by the Windows store) of CA certificates this product added.</summary>
    public List<string> TrustedCaThumbprints { get; set; } = [];
    public string? CurrentCaSha256 { get; set; }

    public string? AppLockerMode { get; set; }          // "local" / "csp" when our policy is applied
    public string? AppLockerPolicySha256 { get; set; }  // which policy was applied (re-applied when the choice changes)
    public int? AppIdSvcOriginalStart { get; set; }
    public Dictionary<string, string?> PolicyBackup { get; set; } = [];

    public DateTimeOffset? LastRekeyAttempt { get; set; }
    public DateTimeOffset? RemovalAuthorizedUntil { get; set; }   // set when a valid removal code was entered
    // Original values of the optional Windows toggles, kept so each can be restored exactly when turned off.
    public Dictionary<string, string?> DesktopExtraBackup { get; set; } = [];
    public PendingRegistration? Registration { get; set; }        // a registration waiting for the administrator

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static MachineState Load()
    {
        try
        {
            if (File.Exists(Paths.StateFile))
            {
                return JsonSerializer.Deserialize<MachineState>(File.ReadAllBytes(Paths.StateFile), Options) ?? new MachineState();
            }
        }
        catch (JsonException)
        {
            // A corrupt state file must not stop protection; secrets and the kill switch live elsewhere.
        }
        return new MachineState();
    }

    public void Save() => SecureDirectory.WriteAllBytesAtomic(Paths.StateFile, JsonSerializer.SerializeToUtf8Bytes(this, Options));
}

/// <summary>What the customer sent in the registration form, kept until the administrator decides.</summary>
internal sealed class PendingRegistration
{
    public string Status { get; set; } = "pending";      // "pending" / "rejected"
    public string Message { get; set; } = string.Empty;
    public int RequestId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Phone { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public int Level { get; set; }
    public List<string> Options { get; set; } = [];
    public string Note { get; set; } = string.Empty;
    public DateTimeOffset SubmittedAt { get; set; }
    public DateTimeOffset? LastChecked { get; set; }
}
