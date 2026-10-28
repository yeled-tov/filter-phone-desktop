using System.Text.Json;

namespace FilterPhone.Core.Tests;

internal static class TestData
{
    public const string ServerKey = "lfTRXEWxt8mZc8cjSvOWN3tqnTpWw4v2Eg3qF6WTklw=";
    public const string Psk = "JRI8Xc0zKP9kXk8qP84NdUQA04h6DLfFbwJn4g+/PFs=";

    /// <summary>Exactly the shape produced by server/filterphone/api/service.py: Services.vpn_config.</summary>
    public static string VpnJson(string allowed = "[\"0.0.0.0/0\", \"::/0\"]", string endpoint = "vpn.filterphone.com:51820",
        string extra = ", \"endpoint_fallback\": \"151.145.88.42:51820\"") => $$"""
        {
          "address": "10.8.0.10/32",
          "dns": ["10.8.0.1"],
          "mtu": 1280,
          "server_public_key": "{{ServerKey}}",
          "preshared_key": "{{Psk}}",
          "endpoint": "{{endpoint}}",
          "allowed_ips": {{allowed}},
          "persistent_keepalive": 25{{extra}}
        }
        """;

    public static JsonElement Element(string json) => JsonDocument.Parse(json).RootElement.Clone();
}
