using System.Globalization;
using System.Net;
using System.Text;

namespace FilterPhone.Core.Vpn;

/// <summary>
/// Renders the wg-quick(8) configuration consumed by the official WireGuard for Windows tunnel service.
/// Every value comes from <see cref="VpnSettings"/> (already validated) or the local key pair, so no
/// untrusted text reaches the file.
/// </summary>
public static class WireGuardConfigWriter
{
    /// <param name="resolvedEndpoint">
    /// The endpoint with its host already resolved to an IP. The kill switch blocks DNS outside the
    /// tunnel, so the tunnel service must not depend on resolving a host name while it is down.
    /// </param>
    public static string Render(VpnSettings vpn, WireGuardKeyPair keys, Endpoint resolvedEndpoint)
    {
        ArgumentNullException.ThrowIfNull(vpn);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(resolvedEndpoint);
        if (!IPAddress.TryParse(resolvedEndpoint.Host, out _))
        {
            throw new ArgumentException("The endpoint must be resolved to an IP address.", nameof(resolvedEndpoint));
        }

        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append("[Interface]\n");
        sb.Append("PrivateKey = ").Append(keys.PrivateKeyBase64()).Append('\n');
        sb.Append("Address = ").AppendJoin(", ", vpn.Addresses).Append('\n');
        sb.Append("DNS = ").AppendJoin(", ", vpn.Dns).Append('\n');
        sb.Append("MTU = ").Append(vpn.Mtu.ToString(inv)).Append('\n');
        sb.Append('\n');
        sb.Append("[Peer]\n");
        sb.Append("PublicKey = ").Append(vpn.ServerPublicKey).Append('\n');
        if (vpn.PresharedKey is not null)
        {
            sb.Append("PresharedKey = ").Append(vpn.PresharedKey).Append('\n');
        }
        sb.Append("AllowedIPs = ").AppendJoin(", ", vpn.AllowedIps).Append('\n');
        sb.Append("Endpoint = ").Append(resolvedEndpoint).Append('\n');
        sb.Append("PersistentKeepalive = ").Append(vpn.PersistentKeepalive.ToString(inv)).Append('\n');
        return sb.ToString();
    }
}
