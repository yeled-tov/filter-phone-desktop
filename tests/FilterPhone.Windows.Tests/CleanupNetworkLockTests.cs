using System.Net;
using System.Net.Sockets;
using FilterPhone.Core.Network;
using FilterPhone.Service;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Network;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Windows.Tests;

/// <summary>
/// Regression for the bug that left a PC permanently offline: the fail-closed WFP lock is persistent, so removing
/// it must never depend on the removal code. A full uninstall still needs the code (protection is not casually
/// removable), but restoring internet (--remove-network-lock) is always allowed. Uses the real Cleanup entry
/// point and a real TEST-NET WFP filter, with the machine state forced to "a removal code is required".
/// </summary>
[Collection("wfp")]
public sealed class CleanupNetworkLockTests : IDisposable
{
    private readonly string _removalKey = Path.Combine(Paths.Secrets, SecretStore.RemovalKey + ".bin");
    private readonly byte[]? _stateBackup;
    private readonly bool _keyExisted;

    public CleanupNetworkLockTests()
    {
        Directory.CreateDirectory(Paths.Secrets);
        Directory.CreateDirectory(Paths.Logs);
        _stateBackup = File.Exists(Paths.StateFile) ? File.ReadAllBytes(Paths.StateFile) : null;
        _keyExisted = File.Exists(_removalKey);

        // Make this PC look enrolled and holding its removal key, with no valid authorization: a code is required.
        File.WriteAllText(Paths.StateFile, "{\"Enrolled\":true}");
        if (!_keyExisted)
        {
            File.WriteAllBytes(_removalKey, [1, 2, 3]);
        }
    }

    public void Dispose()
    {
        WfpKillSwitch.Remove();
        if (_stateBackup is null)
        {
            File.Delete(Paths.StateFile);
        }
        else
        {
            File.WriteAllBytes(Paths.StateFile, _stateBackup);
        }
        if (!_keyExisted)
        {
            File.Delete(_removalKey);
        }
    }

    private static KillSwitchRule BlockTestNet() => new()
    {
        Name = "test: block TEST-NET-1",
        Action = RuleAction.Block,
        Family = AddressFamily.InterNetwork,
        Weight = KillSwitchPlan.BlockWeight,
        RemoteNetworks = [(IPAddress.Parse("192.0.2.0"), 24)],
    };

    [Fact]
    public async Task Removing_the_network_lock_is_never_gated_by_the_removal_code()
    {
        using var loggers = LoggerFactory.Create(_ => { });

        WfpKillSwitch.Apply([BlockTestNet()]);
        Assert.Equal(1, WfpKillSwitch.InstalledFilterCount());

        // A full uninstall is refused without a code — the protection (and the lock) stay in place.
        var full = await Cleanup.RunAsync(loggers, networkLockOnly: false);
        Assert.Equal(Cleanup.RemovalCodeRequired, full);
        Assert.Equal(1, WfpKillSwitch.InstalledFilterCount());

        // Restoring internet is always allowed, even though a code is required and none was entered.
        var net = await Cleanup.RunAsync(loggers, networkLockOnly: true);
        Assert.Equal(0, net);
        Assert.Equal(0, WfpKillSwitch.InstalledFilterCount());
    }
}
