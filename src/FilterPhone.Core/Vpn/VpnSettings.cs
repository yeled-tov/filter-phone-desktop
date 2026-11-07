using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FilterPhone.Core.Vpn;

public sealed record IpNetwork(IPAddress Address, int PrefixLength)
{
    public bool IsDefaultRoute => PrefixLength == 0;

    public override string ToString() => $"{Address}/{PrefixLength.ToString(CultureInfo.InvariantCulture)}";

    public static bool TryParse(string text, out IpNetwork? network)
    {
        network = null;
        var parts = text.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            return false;
        }
        var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max || (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0))
        {
            return false;
        }
        network = new IpNetwork(ip, prefix);
        return true;
    }
}

public sealed record Endpoint(string Host, int Port)
{
    public bool IsIpLiteral => IPAddress.TryParse(Host, out _);

    public override string ToString() =>
        IPAddress.TryParse(Host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{Host}]:{Port.ToString(CultureInfo.InvariantCulture)}"
            : $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
}

public sealed class VpnConfigException(string message) : Exception(message);

/// <summary>
/// The per-device VPN settings returned by <c>POST /v1/enroll</c> ("vpn") and <c>GET /v1/device/vpn</c>,
/// validated. Field names and value ranges follow server/filterphone/api/service.py (vpn_config).
/// Anything that would weaken the full tunnel (split tunnelling, missing IPv6 capture) is rejected.
/// </summary>
public sealed partial class VpnSettings
{
    public required IReadOnlyList<IpNetwork> Addresses { get; init; }
    public required IReadOnlyList<IPAddress> Dns { get; init; }
    public required int Mtu { get; init; }
    public required string ServerPublicKey { get; init; }
    public required string? PresharedKey { get; init; }
    public required Endpoint Endpoint { get; init; }
    public required Endpoint? EndpointFallback { get; init; }
    public required IReadOnlyList<IpNetwork> AllowedIps { get; init; }
    public required int PersistentKeepalive { get; init; }

    /// <summary>The tunnel address the server assigned (e.g. 10.8.0.10). The API reports via_vpn against it.</summary>
    public IPAddress TunnelIPv4 =>
        Addresses.First(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Address;

    public static VpnSettings Parse(JsonElement vpn)
    {
        if (vpn.ValueKind != JsonValueKind.Object)
        {
            throw new VpnConfigException("VPN configuration is missing.");
        }

        var addresses = ParseNetworks(RequiredString(vpn, "address").Split(','), "address");
        if (addresses.Count == 0 || addresses.All(a => a.Address.AddressFamily != AddressFamily.InterNetwork))
        {
            throw new VpnConfigException("VPN configuration has no IPv4 tunnel address.");
        }
        foreach (var a in addresses)
        {
            var hostPrefix = a.Address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (a.PrefixLength != hostPrefix)
            {
                throw new VpnConfigException("VPN tunnel address must be a single host address.");
            }
        }

        if (!vpn.TryGetProperty("dns", out var dnsEl) || dnsEl.ValueKind != JsonValueKind.Array)
        {
            throw new VpnConfigException("VPN configuration has no DNS servers.");
        }
        var dns = new List<IPAddress>();
        foreach (var d in dnsEl.EnumerateArray())
        {
            if (d.ValueKind != JsonValueKind.String || !IPAddress.TryParse(d.GetString(), out var ip)
                || (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0))
            {
                throw new VpnConfigException("VPN DNS server is not an IP address.");
            }
            dns.Add(ip);
        }
        if (dns.Count is 0 or > 4)
        {
            throw new VpnConfigException("VPN configuration must have 1-4 DNS servers.");
        }

        var mtu = OptionalInt(vpn, "mtu") ?? 1280;
        if (mtu is < 1280 or > 1500)
        {
            throw new VpnConfigException("VPN MTU is out of range.");
        }

        var serverKey = RequiredString(vpn, "server_public_key");
        if (!WireGuardKeys.IsValidKey(serverKey))
        {
            throw new VpnConfigException("VPN server public key is invalid.");
        }

        string? psk = null;
        if (vpn.TryGetProperty("preshared_key", out var pskEl) && pskEl.ValueKind == JsonValueKind.String
            && pskEl.GetString() is { Length: > 0 } pskText)
        {
            if (!WireGuardKeys.IsValidKey(pskText))
            {
                throw new VpnConfigException("VPN preshared key is invalid.");
            }
            psk = pskText;
        }

        var endpoint = ParseEndpoint(RequiredString(vpn, "endpoint"))
            ?? throw new VpnConfigException("VPN endpoint is invalid.");
        Endpoint? fallback = null;
        if (vpn.TryGetProperty("endpoint_fallback", out var fbEl) && fbEl.ValueKind == JsonValueKind.String
            && fbEl.GetString() is { Length: > 0 } fbText)
        {
            fallback = ParseEndpoint(fbText);
            if (fallback is null || !fallback.IsIpLiteral)
            {
                throw new VpnConfigException("VPN fallback endpoint must be an IP address.");
            }
        }

        if (!vpn.TryGetProperty("allowed_ips", out var aipEl) || aipEl.ValueKind != JsonValueKind.Array)
        {
            throw new VpnConfigException("VPN allowed IPs are missing.");
        }
        var allowed = ParseNetworks(aipEl.EnumerateArray().Select(e =>
            e.ValueKind == JsonValueKind.String ? e.GetString() ?? string.Empty : string.Empty), "allowed_ips");
        // Full tunnel for both families: anything less would let traffic leave outside the filter.
        if (!allowed.Any(n => n.IsDefaultRoute && n.Address.AddressFamily == AddressFamily.InterNetwork)
            || !allowed.Any(n => n.IsDefaultRoute && n.Address.AddressFamily == AddressFamily.InterNetworkV6))
        {
            throw new VpnConfigException("VPN configuration is not a full tunnel (0.0.0.0/0 and ::/0 required).");
        }

        var keepalive = OptionalInt(vpn, "persistent_keepalive") ?? 25;
        if (keepalive is < 10 or > 120)
        {
            throw new VpnConfigException("VPN keepalive is out of range.");
        }

        return new VpnSettings
        {
            Addresses = addresses,
            Dns = dns,
            Mtu = mtu,
            ServerPublicKey = serverKey,
            PresharedKey = psk,
            Endpoint = endpoint,
            EndpointFallback = fallback,
            AllowedIps = allowed,
            PersistentKeepalive = keepalive,
        };
    }

    /// <summary>
    /// Stable fingerprint of the server-side settings (no private key), used to detect configuration
    /// changes without storing or comparing secrets in logs.
    /// </summary>
    public string Fingerprint()
    {
        var sb = new StringBuilder();
        sb.AppendJoin(',', Addresses).Append('|').AppendJoin(',', Dns).Append('|').Append(Mtu).Append('|')
            .Append(ServerPublicKey).Append('|').Append(PresharedKey).Append('|').Append(Endpoint).Append('|')
            .Append(EndpointFallback).Append('|').AppendJoin(',', AllowedIps).Append('|').Append(PersistentKeepalive);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())))[..16];
    }

    public static Endpoint? ParseEndpoint(string text)
    {
        text = text.Trim();
        string host;
        string portText;
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 0 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return null;
            }
            host = text[1..close];
            portText = text[(close + 2)..];
            if (!IPAddress.TryParse(host, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return null;
            }
        }
        else
        {
            var colon = text.LastIndexOf(':');
            if (colon <= 0 || text.IndexOf(':', StringComparison.Ordinal) != colon)
            {
                return null;
            }
            host = text[..colon];
            portText = text[(colon + 1)..];
            if (!IPAddress.TryParse(host, out _) && !HostName().IsMatch(host))
            {
                return null;
            }
        }
        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            return null;
        }
        return new Endpoint(host.ToLowerInvariant(), port);
    }

    private static List<IpNetwork> ParseNetworks(IEnumerable<string> items, string field)
    {
        var list = new List<IpNetwork>();
        foreach (var raw in items)
        {
            if (string.IsNullOrWhiteSpace(raw) || !IpNetwork.TryParse(raw, out var n) || n is null)
            {
                throw new VpnConfigException($"VPN field '{field}' contains an invalid network.");
            }
            list.Add(n);
        }
        return list;
    }

    private static string RequiredString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String
            || el.GetString() is not { Length: > 0 and <= 512 } s)
        {
            throw new VpnConfigException($"VPN field '{name}' is missing.");
        }
        return s;
    }

    private static int? OptionalInt(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (el.ValueKind != JsonValueKind.Number || !el.TryGetInt32(out var v))
        {
            throw new VpnConfigException($"VPN field '{name}' is not a number.");
        }
        return v;
    }

    // RFC 1123 host name (letters, digits, hyphens; dot-separated labels).
    [GeneratedRegex(@"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")]
    private static partial Regex HostName();
}
