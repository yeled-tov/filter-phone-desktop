namespace FilterPhone.Core.Status;

/// <summary>Inputs that are not layer checks but influence the overall state.</summary>
public sealed record EvaluationContext(
    bool Enrolled,
    string? ServerStatus,
    bool TunnelEverUp,
    bool ApiReachable,
    DateTimeOffset Now)
{
    /// <summary>"pending" / "rejected" while a registration waits for the administrator; otherwise null.</summary>
    public string? Registration { get; init; }
}

/// <summary>
/// Turns independent layer checks into one honest overall state. "Protected" is returned only when every
/// layer passed and the verification is fresh; a successful handshake or API call alone is never enough.
/// </summary>
public static class ProtectionEvaluator
{
    /// <summary>Verification results older than this no longer count as proof.</summary>
    public static readonly TimeSpan MaxVerificationAge = TimeSpan.FromHours(2);

    /// <summary>Layers proven by periodic end-to-end probes; their results expire.</summary>
    private static readonly HashSet<string> PeriodicLayers =
        [Status.Layers.ServerPath, Status.Layers.Interception, Status.Layers.ImagePath, Status.Layers.ChromeOnly,
         Status.Layers.StoreBlock];

    private static readonly string[] VerifiedLayers =
        [Status.Layers.Tunnel, Status.Layers.ServerPath, Status.Layers.KillSwitch, Status.Layers.CaTrust,
         Status.Layers.Interception, Status.Layers.ImagePath, Status.Layers.ChromePolicy];

    public static OverallState Evaluate(IReadOnlyDictionary<string, LayerCheck> checks, EvaluationContext ctx)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(ctx);
        LayerCheck Get(string layer) => checks.TryGetValue(layer, out var c) ? c : LayerCheck.Unknown(layer);
        CheckState Fresh(string layer)
        {
            var c = Get(layer);
            if (c.State == CheckState.Ok && PeriodicLayers.Contains(layer)
                && (c.CheckedAt is null || ctx.Now - c.CheckedAt > MaxVerificationAge))
            {
                return CheckState.Pending;
            }
            return c.State;
        }

        if (!ctx.Enrolled)
        {
            return ctx.Registration switch
            {
                "pending" => OverallState.AwaitingApproval,
                "rejected" => OverallState.RegistrationRejected,
                _ => OverallState.NotEnrolled,
            };
        }
        if (ctx.ServerStatus is { Length: > 0 } s && s != "active")
        {
            return OverallState.DeviceInactive;
        }

        // Fail-closed setup must be complete before anything else can be called protection.
        var kill = Get(Status.Layers.KillSwitch).State;
        if (kill == CheckState.Failed)
        {
            return OverallState.AdminActionRequired;
        }
        var ca = Get(Status.Layers.CaTrust).State;
        if (ca == CheckState.Failed)
        {
            return OverallState.AdminActionRequired;
        }

        var tunnel = Get(Status.Layers.Tunnel).State;
        if (tunnel != CheckState.Ok)
        {
            if (!ctx.TunnelEverUp)
            {
                return kill == CheckState.Ok || ca == CheckState.Ok ? OverallState.Connecting : OverallState.SetupIncomplete;
            }
            return ctx.ApiReachable ? OverallState.Reconnecting : OverallState.ServerUnavailable;
        }

        if (kill != CheckState.Ok || ca != CheckState.Ok)
        {
            return OverallState.SetupIncomplete;
        }

        var path = Fresh(Status.Layers.ServerPath);
        if (path == CheckState.Failed)
        {
            return OverallState.ServerUnavailable;
        }
        if (Fresh(Status.Layers.Interception) == CheckState.Failed || Fresh(Status.Layers.ImagePath) == CheckState.Failed)
        {
            return OverallState.FilteringTestFailed;
        }
        if (Get(Status.Layers.ChromeOnly).State == CheckState.Failed || Get(Status.Layers.ChromePolicy).State == CheckState.Failed
            || Get(Status.Layers.StoreBlock).State == CheckState.Failed)
        {
            return OverallState.AdminActionRequired;
        }
        if (VerifiedLayers.Any(l => Fresh(l) != CheckState.Ok))
        {
            return OverallState.Connecting;
        }
        // Device-control layers: each must be proven, or be a known limitation of this Windows edition.
        var device = new[] { Fresh(Status.Layers.ChromeOnly), Fresh(Status.Layers.StoreBlock) };
        if (device.All(s => s == CheckState.Ok))
        {
            return OverallState.Protected;
        }
        return device.All(s => s is CheckState.Ok or CheckState.Unsupported)
            ? OverallState.ProtectedWithLimitations
            : OverallState.Connecting;
    }
}
