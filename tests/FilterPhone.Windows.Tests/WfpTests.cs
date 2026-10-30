using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using FilterPhone.Core.Network;
using FilterPhone.Service.Native;
using FilterPhone.Service.Network;

namespace FilterPhone.Windows.Tests;

public class WfpLayoutTests
{
    // Expected values: wireguard-windows tunnel/firewall/types_windows_64.go (x64).
    [Fact]
    public void Struct_sizes_and_offsets_match_the_windows_headers()
    {
        Assert.Equal(16, Marshal.SizeOf<FWP_BYTE_BLOB>());
        Assert.Equal(16, Marshal.SizeOf<FWP_VALUE0>());
        Assert.Equal(8, (int)Marshal.OffsetOf<FWP_VALUE0>(nameof(FWP_VALUE0.value)));
        Assert.Equal(40, Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
        Assert.Equal(16, (int)Marshal.OffsetOf<FWPM_FILTER_CONDITION0>(nameof(FWPM_FILTER_CONDITION0.matchType)));
        Assert.Equal(24, (int)Marshal.OffsetOf<FWPM_FILTER_CONDITION0>(nameof(FWPM_FILTER_CONDITION0.conditionValue)));
        Assert.Equal(200, Marshal.SizeOf<FWPM_FILTER0>());
        Assert.Equal(32, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.flags)));
        Assert.Equal(40, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.providerKey)));
        Assert.Equal(64, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.layerKey)));
        Assert.Equal(96, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.weight)));
        Assert.Equal(112, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.numFilterConditions)));
        Assert.Equal(120, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.filterCondition)));
        Assert.Equal(128, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.action)));
        Assert.Equal(152, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.context)));
        Assert.Equal(176, (int)Marshal.OffsetOf<FWPM_FILTER0>(nameof(FWPM_FILTER0.filterId)));
        Assert.Equal(72, Marshal.SizeOf<FWPM_SUBLAYER0>());
        Assert.Equal(64, (int)Marshal.OffsetOf<FWPM_SUBLAYER0>(nameof(FWPM_SUBLAYER0.weight)));
        Assert.Equal(64, Marshal.SizeOf<FWPM_PROVIDER0>());
        Assert.Equal(56, (int)Marshal.OffsetOf<FWPM_PROVIDER0>(nameof(FWPM_PROVIDER0.serviceName)));
        Assert.Equal(8, Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
        Assert.Equal(17, Marshal.SizeOf<FWP_V6_ADDR_AND_MASK>());
    }

    [Fact]
    public void Filter_keys_are_deterministic_and_distinct()
    {
        var keys = Enumerable.Range(0, WfpKillSwitch.MaxFilters).Select(WfpKillSwitch.FilterKey).ToList();
        Assert.Equal(keys.Count, keys.Distinct().Count());
        Assert.Equal(WfpKillSwitch.FilterKey(3), WfpKillSwitch.FilterKey(3));
    }
}

/// <summary>
/// Installs real persistent WFP filters through the production code path, but scoped to documentation-only
/// address ranges (RFC 5737 TEST-NET), so the runner's own connectivity is never affected.
/// </summary>
[Collection("wfp")]
public sealed class WfpKillSwitchIntegrationTests : IDisposable
{
    private static readonly IPAddress Blocked = IPAddress.Parse("192.0.2.10");     // TEST-NET-1
    private static readonly IPAddress Permitted = IPAddress.Parse("192.0.2.20");

    public void Dispose() => WfpKillSwitch.Remove();

    private static KillSwitchRule BlockTestNet() => new()
    {
        Name = "test: block TEST-NET-1",
        Action = RuleAction.Block,
        Family = AddressFamily.InterNetwork,
        Weight = KillSwitchPlan.BlockWeight,
        RemoteNetworks = [(IPAddress.Parse("192.0.2.0"), 24)],
    };

    private static KillSwitchRule PermitOne() => new()
    {
        Name = "test: permit one host",
        Action = RuleAction.Permit,
        Family = AddressFamily.InterNetwork,
        Weight = KillSwitchPlan.PermitWeight,
        Protocol = RuleProtocol.Tcp,
        RemotePort = 80,
        RemoteNetworks = [(Permitted, 32)],
    };

    private static SocketError Connect(IPAddress ip)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var task = s.ConnectAsync(new IPEndPoint(ip, 80));
            if (!task.Wait(TimeSpan.FromSeconds(3)))
            {
                return SocketError.TimedOut;
            }
            return SocketError.Success;
        }
        catch (AggregateException e) when (e.InnerException is SocketException se)
        {
            return se.SocketErrorCode;
        }
    }

    [Fact]
    public void Block_and_higher_weight_permit_take_effect_and_are_removed_exactly()
    {
        WfpKillSwitch.Remove();
        Assert.Equal(0, WfpKillSwitch.InstalledFilterCount());

        WfpKillSwitch.Apply([BlockTestNet(), PermitOne()]);
        Assert.Equal(2, WfpKillSwitch.InstalledFilterCount());

        // Blocked by our filter: Windows refuses the connection immediately (WSAEACCES), no packet is sent.
        Assert.Equal(SocketError.AccessDenied, Connect(Blocked));
        // The permit outweighs the block: the connection attempt is allowed out (TEST-NET never answers).
        Assert.NotEqual(SocketError.AccessDenied, Connect(Permitted));

        // Re-applying is idempotent and replaces the set.
        WfpKillSwitch.Apply([BlockTestNet()]);
        Assert.Equal(1, WfpKillSwitch.InstalledFilterCount());
        Assert.Equal(SocketError.AccessDenied, Connect(Permitted));

        WfpKillSwitch.Remove();
        Assert.Equal(0, WfpKillSwitch.InstalledFilterCount());
        Assert.NotEqual(SocketError.AccessDenied, Connect(Blocked));
        WfpKillSwitch.Remove();     // removing twice is safe
    }

    [Fact]
    public void Application_and_ipv6_conditions_are_accepted_by_wfp()
    {
        var self = Environment.ProcessPath!;
        WfpKillSwitch.Apply(
        [
            new KillSwitchRule
            {
                Name = "test: app-scoped permit", Action = RuleAction.Permit, Family = AddressFamily.InterNetwork,
                Weight = KillSwitchPlan.PermitWeight, Protocol = RuleProtocol.Tcp, RemotePort = 443, ApplicationPath = self,
                RemoteNetworks = [(IPAddress.Parse("198.51.100.1"), 32)],
            },
            new KillSwitchRule
            {
                Name = "test: ipv6 doc range", Action = RuleAction.Block, Family = AddressFamily.InterNetworkV6,
                Weight = KillSwitchPlan.BlockWeight, RemoteNetworks = [(IPAddress.Parse("2001:db8::"), 32)],
            },
            new KillSwitchRule
            {
                Name = "test: icmpv6 link local", Action = RuleAction.Permit, Family = AddressFamily.InterNetworkV6,
                Weight = KillSwitchPlan.PermitWeight, Protocol = RuleProtocol.IcmpV6,
                RemoteNetworks = [(IPAddress.Parse("fe80::"), 10), (IPAddress.Parse("ff02::"), 16)],
            },
            new KillSwitchRule
            {
                Name = "test: loopback + local address", Action = RuleAction.Permit, Family = AddressFamily.InterNetwork,
                Weight = KillSwitchPlan.PermitWeight, LocalAddress = IPAddress.Parse("192.0.2.99"), LocalPort = 68,
            },
        ]);
        Assert.Equal(4, WfpKillSwitch.InstalledFilterCount());
    }

    [Fact]
    public void The_production_plan_is_accepted_by_wfp_when_scoped_to_test_addresses()
    {
        // The full production rule set, minus the two block-all rules (which would cut the runner off).
        var plan = KillSwitchPlan.Build(new KillSwitchInputs(IPAddress.Parse("192.0.2.50"), [IPAddress.Parse("192.0.2.51")], 51820,
            [IPAddress.Parse("192.0.2.52")], Environment.ProcessPath!));
        var withoutBlockAll = plan.Where(r => r.Action == RuleAction.Permit).ToList();
        WfpKillSwitch.Apply(withoutBlockAll);
        Assert.Equal(withoutBlockAll.Count, WfpKillSwitch.InstalledFilterCount());
        Assert.Contains(plan, r => r.Action == RuleAction.Block && r.Family == AddressFamily.InterNetwork);
        Assert.Contains(plan, r => r.Action == RuleAction.Block && r.Family == AddressFamily.InterNetworkV6);
    }
}
