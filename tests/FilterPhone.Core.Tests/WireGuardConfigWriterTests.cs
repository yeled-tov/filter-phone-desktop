using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

public class WireGuardConfigWriterTests
{
    [Fact]
    public void Renders_a_full_tunnel_wg_quick_configuration()
    {
        var vpn = VpnSettings.Parse(TestData.Element(TestData.VpnJson()));
        using var keys = WireGuardKeys.Generate();
        var conf = WireGuardConfigWriter.Render(vpn, keys, new Endpoint("151.145.88.42", 51820));
        var expected =
            "[Interface]\n" +
            $"PrivateKey = {keys.PrivateKeyBase64()}\n" +
            "Address = 10.8.0.10/32\n" +
            "DNS = 10.8.0.1\n" +
            "MTU = 1280\n" +
            "\n" +
            "[Peer]\n" +
            $"PublicKey = {TestData.ServerKey}\n" +
            $"PresharedKey = {TestData.Psk}\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\n" +
            "Endpoint = 151.145.88.42:51820\n" +
            "PersistentKeepalive = 25\n";
        Assert.Equal(expected, conf);
        Assert.DoesNotContain("PostUp", conf, StringComparison.Ordinal);
        Assert.DoesNotContain("Table", conf, StringComparison.Ordinal);
    }

    [Fact]
    public void Requires_a_resolved_endpoint()
    {
        var vpn = VpnSettings.Parse(TestData.Element(TestData.VpnJson()));
        using var keys = WireGuardKeys.Generate();
        Assert.Throws<ArgumentException>(() => WireGuardConfigWriter.Render(vpn, keys, vpn.Endpoint));
    }
}

public class WgShowParserTests
{
    [Fact]
    public void Parses_latest_handshakes_and_transfer()
    {
        var hs = WgShowParser.ParseLatestHandshakes($"{TestData.ServerKey}\t1700000000\r\n{TestData.Psk}\t0\n garbage line\n");
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), hs[TestData.ServerKey]);
        Assert.Null(hs[TestData.Psk]);
        Assert.Equal(2, hs.Count);

        var tr = WgShowParser.ParseTransfer($"{TestData.ServerKey}\t123\t456\n");
        Assert.Equal((123L, 456L), tr[TestData.ServerKey]);
    }
}
