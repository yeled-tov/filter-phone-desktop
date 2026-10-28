using FilterPhone.Core.Status;

namespace FilterPhone.Core.Tests;

public class EvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);

    private static Dictionary<string, LayerCheck> AllOk(DateTimeOffset? at = null) =>
        Layers.All.ToDictionary(l => l, l => new LayerCheck(l, CheckState.Ok, "ok", at ?? Now));

    private static EvaluationContext Ctx(bool enrolled = true, string status = "active", bool everUp = true, bool api = true) =>
        new(enrolled, status, everUp, api, Now);

    private static OverallState With(string layer, CheckState state, EvaluationContext? ctx = null)
    {
        var checks = AllOk();
        checks[layer] = new LayerCheck(layer, state, "x", Now);
        return ProtectionEvaluator.Evaluate(checks, ctx ?? Ctx());
    }

    [Fact]
    public void Protected_only_when_every_layer_is_verified() =>
        Assert.Equal(OverallState.Protected, ProtectionEvaluator.Evaluate(AllOk(), Ctx()));

    [Fact]
    public void Not_enrolled_and_inactive_devices()
    {
        Assert.Equal(OverallState.NotEnrolled, ProtectionEvaluator.Evaluate(AllOk(), Ctx(enrolled: false)));
        Assert.Equal(OverallState.DeviceInactive, ProtectionEvaluator.Evaluate(AllOk(), Ctx(status: "disabled")));
    }

    [Fact]
    public void A_handshake_alone_is_not_protection()
    {
        var checks = Layers.All.ToDictionary(l => l, LayerCheck.Unknown);
        checks[Layers.Tunnel] = new LayerCheck(Layers.Tunnel, CheckState.Ok, "handshake", Now);
        checks[Layers.KillSwitch] = new LayerCheck(Layers.KillSwitch, CheckState.Ok, "ok", Now);
        checks[Layers.CaTrust] = new LayerCheck(Layers.CaTrust, CheckState.Ok, "ok", Now);
        Assert.Equal(OverallState.Connecting, ProtectionEvaluator.Evaluate(checks, Ctx()));
    }

    [Fact]
    public void Filtering_failures_are_failures() =>
        Assert.Equal(OverallState.FilteringTestFailed, With(Layers.ImagePath, CheckState.Failed));

    [Fact]
    public void Interception_failure_is_a_filtering_failure() =>
        Assert.Equal(OverallState.FilteringTestFailed, With(Layers.Interception, CheckState.Failed));

    [Fact]
    public void Tunnel_down_states()
    {
        Assert.Equal(OverallState.Reconnecting, With(Layers.Tunnel, CheckState.Failed));
        Assert.Equal(OverallState.ServerUnavailable, With(Layers.Tunnel, CheckState.Failed, Ctx(api: false)));
        Assert.Equal(OverallState.Connecting, With(Layers.Tunnel, CheckState.Pending, Ctx(everUp: false)));
    }

    [Fact]
    public void Missing_kill_switch_or_ca_is_not_protected()
    {
        Assert.Equal(OverallState.SetupIncomplete, With(Layers.KillSwitch, CheckState.Pending));
        Assert.Equal(OverallState.AdminActionRequired, With(Layers.KillSwitch, CheckState.Failed));
        Assert.Equal(OverallState.AdminActionRequired, With(Layers.CaTrust, CheckState.Failed));
    }

    [Fact]
    public void Chrome_only_unsupported_is_shown_as_a_limitation()
    {
        Assert.Equal(OverallState.ProtectedWithLimitations, With(Layers.ChromeOnly, CheckState.Unsupported));
        Assert.Equal(OverallState.AdminActionRequired, With(Layers.ChromeOnly, CheckState.Failed));
    }

    [Fact]
    public void Stale_verification_is_not_proof() =>
        Assert.Equal(OverallState.Connecting,
            ProtectionEvaluator.Evaluate(AllOk(Now - TimeSpan.FromHours(3)), Ctx()));

    [Fact]
    public void Server_path_failure_means_server_unavailable() =>
        Assert.Equal(OverallState.ServerUnavailable, With(Layers.ServerPath, CheckState.Failed));
}
