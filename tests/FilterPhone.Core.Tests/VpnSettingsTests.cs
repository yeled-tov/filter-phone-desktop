using System.Net;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

public class VpnSettingsTests
{
    [Fact]
    public void Parses_the_server_configuration()
    {
        var vpn = VpnSettings.Parse(TestData.Element(TestData.VpnJson()));
        Assert.Equal(IPAddress.Parse("10.8.0.10"), vpn.TunnelIPv4);
        Assert.Equal([IPAddress.Parse("10.8.0.1")], vpn.Dns);
        Assert.Equal(1280, vpn.Mtu);
        Assert.Equal(new Endpoint("vpn.filterphone.com", 51820), vpn.Endpoint);
        Assert.Equal(new Endpoint("151.145.88.42", 51820), vpn.EndpointFallback);
        Assert.Equal(25, vpn.PersistentKeepalive);
        Assert.Equal(TestData.Psk, vpn.PresharedKey);
    }

    [Fact]
    public void Fallback_endpoint_is_optional()
    {
        var vpn = VpnSettings.Parse(TestData.Element(TestData.VpnJson(extra: "")));
        Assert.Null(vpn.EndpointFallback);
    }

    [Theory]
    [InlineData("[\"0.0.0.0/0\"]")]                       // IPv6 would escape outside the tunnel
    [InlineData("[\"::/0\"]")]
    [InlineData("[\"0.0.0.0/1\", \"128.0.0.0/1\", \"::/0\"]")]
    [InlineData("[\"10.0.0.0/8\", \"::/0\"]")]
    [InlineData("[]")]
    public void Split_tunnels_are_rejected(string allowed) =>
        Assert.Throws<VpnConfigException>(() => VpnSettings.Parse(TestData.Element(TestData.VpnJson(allowed))));

    [Theory]
    [InlineData("vpn.filterphone.com")]
    [InlineData("vpn.filterphone.com:0")]
    [InlineData("vpn.filterphone.com:70000")]
    [InlineData("vpn filterphone.com:51820")]
    [InlineData("vpn.filterphone.com:51820\\nPostUp = calc.exe")]
    [InlineData("::1:51820")]
    public void Invalid_endpoints_are_rejected(string endpoint) =>
        Assert.Throws<VpnConfigException>(() => VpnSettings.Parse(TestData.Element(TestData.VpnJson(endpoint: endpoint))));

    [Fact]
    public void Bracketed_ipv6_endpoint_is_accepted()
    {
        var vpn = VpnSettings.Parse(TestData.Element(TestData.VpnJson(endpoint: "[2001:db8::1]:51820")));
        Assert.Equal("[2001:db8::1]:51820", vpn.Endpoint.ToString());
    }

    [Fact]
    public void Fallback_must_be_an_ip_address() =>
        Assert.Throws<VpnConfigException>(() => VpnSettings.Parse(TestData.Element(
            TestData.VpnJson(extra: ", \"endpoint_fallback\": \"evil.example:51820\""))));

    [Theory]
    [InlineData("\"address\": \"10.8.0.10/32\"", "\"address\": \"10.8.0.0/24\"")]
    [InlineData("\"address\": \"10.8.0.10/32\"", "\"address\": \"fd00::1/128\"")]
    [InlineData("\"mtu\": 1280", "\"mtu\": 9000")]
    [InlineData("\"dns\": [\"10.8.0.1\"]", "\"dns\": []")]
    [InlineData("\"dns\": [\"10.8.0.1\"]", "\"dns\": [\"dns.example\"]")]
    [InlineData("\"persistent_keepalive\": 25", "\"persistent_keepalive\": 1")]
    [InlineData("\"server_public_key\": \"" + TestData.ServerKey + "\"", "\"server_public_key\": \"short\"")]
    [InlineData("\"preshared_key\": \"" + TestData.Psk + "\"", "\"preshared_key\": \"x\"")]
    public void Invalid_fields_are_rejected(string from, string to) =>
        Assert.Throws<VpnConfigException>(() => VpnSettings.Parse(TestData.Element(TestData.VpnJson().Replace(from, to))));

    [Fact]
    public void Fingerprint_changes_when_server_settings_change()
    {
        var a = VpnSettings.Parse(TestData.Element(TestData.VpnJson())).Fingerprint();
        var b = VpnSettings.Parse(TestData.Element(TestData.VpnJson())).Fingerprint();
        var c = VpnSettings.Parse(TestData.Element(TestData.VpnJson(endpoint: "vpn2.filterphone.com:51820"))).Fingerprint();
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
        Assert.DoesNotContain(TestData.Psk, a, StringComparison.Ordinal);
    }
}
