using System.Net;
using System.Net.Sockets;

namespace FilterPhone.Core.Network;

public enum RuleAction
{
    Permit,
    Block,
}

public enum RuleProtocol
{
    Any = 0,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    IcmpV6 = 58,
}

/// <summary>
/// One outbound connection-authorisation rule (WFP layer ALE_AUTH_CONNECT_V4/V6). The service maps each
/// rule to exactly one persistent WFP filter in the FilterPhone sub-layer; nothing outside that
/// sub-layer is created, so removal is exact and never touches other firewall rules.
/// </summary>
public sealed record KillSwitchRule
{
    public required string Name { get; init; }
    public required RuleAction Action { get; init; }
    public required AddressFamily Family { get; init; }
    public required byte Weight { get; init; }
    public bool Loopback { get; init; }
    public RuleProtocol Protocol { get; init; } = RuleProtocol.Any;
    public IPAddress? LocalAddress { get; init; }
    public IReadOnlyList<(IPAddress Address, int Prefix)> RemoteNetworks { get; init; } = [];
    public ushort? LocalPort { get; init; }
    public ushort? RemotePort { get; init; }
    /// <summary>Full path of the executable the rule is restricted to (WFP app id).</summary>
    public string? ApplicationPath { get; init; }
}

public sealed record KillSwitchInputs(
    IPAddress TunnelAddress,
    IReadOnlyList<IPAddress> EndpointAddresses,
    ushort EndpointPort,
    IReadOnlyList<IPAddress> ApiAddresses,
    string ServiceExecutablePath);

/// <summary>
/// The fail-closed network policy (documented in docs/SECURITY.md#kill-switch):
/// while it is installed, an outbound connection is allowed only if it is
///   1. loopback,
///   2. DHCP / DHCPv6 / IPv6 neighbour discovery on the local link (network setup),
///   3. sourced from the tunnel address (i.e. it goes through the WireGuard tunnel),
///   4. WireGuard's own UDP to the FilterPhone VPN endpoint,
///   5. the FilterPhone service itself reaching the FilterPhone API on TCP 443 (re-key / recovery).
/// Everything else, IPv4 and IPv6, is blocked. Inbound connections are left to Windows Firewall so a local
/// administrator recovery path (e.g. Remote Desktop from the LAN) keeps working.
/// </summary>
public static class KillSwitchPlan
{
    public const byte PermitWeight = 12;
    public const byte BlockWeight = 1;

    public static IReadOnlyList<KillSwitchRule> Build(KillSwitchInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (inputs.TunnelAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("The tunnel address must be IPv4.", nameof(inputs));
        }
        if (inputs.EndpointAddresses.Count == 0)
        {
            throw new ArgumentException("At least one VPN endpoint address is required.", nameof(inputs));
        }
        if (!IsAbsoluteWindowsPath(inputs.ServiceExecutablePath))
        {
            throw new ArgumentException("The service path must be absolute.", nameof(inputs));
        }

        var v4 = AddressFamily.InterNetwork;
        var v6 = AddressFamily.InterNetworkV6;
        var rules = new List<KillSwitchRule>
        {
            new() { Name = "Permit loopback (IPv4)", Action = RuleAction.Permit, Family = v4, Weight = PermitWeight, Loopback = true },
            new() { Name = "Permit loopback (IPv6)", Action = RuleAction.Permit, Family = v6, Weight = PermitWeight, Loopback = true },
            new()
            {
                Name = "Permit DHCP (IPv4)", Action = RuleAction.Permit, Family = v4, Weight = PermitWeight,
                Protocol = RuleProtocol.Udp, LocalPort = 68, RemotePort = 67,
            },
            new()
            {
                Name = "Permit DHCPv6", Action = RuleAction.Permit, Family = v6, Weight = PermitWeight,
                Protocol = RuleProtocol.Udp, LocalPort = 546, RemotePort = 547,
            },
            new()
            {
                Name = "Permit IPv6 neighbour discovery on the local link", Action = RuleAction.Permit, Family = v6,
                Weight = PermitWeight, Protocol = RuleProtocol.IcmpV6,
                RemoteNetworks = [(IPAddress.Parse("fe80::"), 10), (IPAddress.Parse("ff02::"), 16)],
            },
            new()
            {
                Name = "Permit traffic through the FilterPhone tunnel", Action = RuleAction.Permit, Family = v4,
                Weight = PermitWeight, LocalAddress = inputs.TunnelAddress,
            },
        };

        foreach (var group in inputs.EndpointAddresses.Distinct().GroupBy(a => a.AddressFamily))
        {
            rules.Add(new KillSwitchRule
            {
                Name = $"Permit WireGuard to the FilterPhone VPN endpoint ({(group.Key == v4 ? "IPv4" : "IPv6")})",
                Action = RuleAction.Permit,
                Family = group.Key,
                Weight = PermitWeight,
                Protocol = RuleProtocol.Udp,
                RemotePort = inputs.EndpointPort,
                RemoteNetworks = group.Select(a => (a, a.AddressFamily == v4 ? 32 : 128)).ToList(),
            });
        }

        foreach (var group in inputs.ApiAddresses.Distinct().GroupBy(a => a.AddressFamily))
        {
            rules.Add(new KillSwitchRule
            {
                Name = $"Permit the FilterPhone service to reach the FilterPhone API ({(group.Key == v4 ? "IPv4" : "IPv6")})",
                Action = RuleAction.Permit,
                Family = group.Key,
                Weight = PermitWeight,
                Protocol = RuleProtocol.Tcp,
                RemotePort = 443,
                ApplicationPath = inputs.ServiceExecutablePath,
                RemoteNetworks = group.Select(a => (a, a.AddressFamily == v4 ? 32 : 128)).ToList(),
            });
        }

        rules.Add(new() { Name = "Block all other outbound traffic (IPv4)", Action = RuleAction.Block, Family = v4, Weight = BlockWeight });
        rules.Add(new() { Name = "Block all other outbound traffic (IPv6)", Action = RuleAction.Block, Family = v6, Weight = BlockWeight });
        return rules;
    }

    // The plan is built (and unit-tested) on any OS, but the path is always a Windows path.
    private static bool IsAbsoluteWindowsPath(string path) =>
        path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        && !path.Contains("..", StringComparison.Ordinal);
}
