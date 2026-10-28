using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FilterPhone.Core.Api;
using FilterPhone.Core.Trust;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

/// <summary>
/// Contract tests against the real FilterPhone API code (tests/contract/backend_harness.py runs
/// yeled-tov/filterphone/server at a pinned commit with its own WireGuard/Redis test doubles).
/// Run with: dotnet test --filter Category=Contract, with FP_CONTRACT_INFO pointing at the harness info file.
/// These tests fail (they do not silently pass) when the harness is not running.
/// </summary>
[Trait("Category", "Contract")]
public sealed class BackendContractTests : IDisposable
{
    private readonly Info _info;
    private readonly FilterPhoneApiClient _client;

    private sealed record Info(string BaseUrl, string Code, string AdminUser, string AdminPassword);

    public BackendContractTests()
    {
        var path = Environment.GetEnvironmentVariable("FP_CONTRACT_INFO");
        Assert.False(string.IsNullOrEmpty(path), "FP_CONTRACT_INFO is not set: start tests/contract/backend_harness.py first.");
        using var doc = JsonDocument.Parse(File.ReadAllText(path!));
        var r = doc.RootElement;
        _info = new Info(r.GetProperty("base_url").GetString()!, r.GetProperty("code").GetString()!,
            r.GetProperty("admin_user").GetString()!, r.GetProperty("admin_password").GetString()!);
        _client = new FilterPhoneApiClient(new Uri(_info.BaseUrl));
    }

    public void Dispose() => _client.Dispose();

    private static string Uid() => Convert.ToHexStringLower(Guid.NewGuid().ToByteArray());

    [Fact]
    public async Task Invalid_activation_code_is_refused()
    {
        using var keys = WireGuardKeys.Generate();
        var e = await Assert.ThrowsAsync<ApiException>(() => _client.EnrollAsync("WRONG-CODE1", keys.PublicKey, "pc", Uid(), default));
        Assert.Equal(ApiErrorKind.Forbidden, e.Kind);
        Assert.False(string.IsNullOrEmpty(e.ServerMessage));
    }

    [Fact]
    public async Task Valid_enrollment_returns_a_usable_full_tunnel_configuration_and_ca()
    {
        using var keys = WireGuardKeys.Generate();
        var result = await _client.EnrollAsync(_info.Code, keys.PublicKey, "Contract PC", Uid(), default);

        Assert.Equal("active", result.Status);
        Assert.Equal(2, result.Level);
        Assert.StartsWith("10.8.0.", result.Vpn.TunnelIPv4.ToString(), StringComparison.Ordinal);
        Assert.Equal("vpn.filterphone.com", result.Vpn.Endpoint.Host);
        Assert.NotNull(result.Vpn.EndpointFallback);
        Assert.True(result.Vpn.EndpointFallback!.IsIpLiteral);
        var ca = CaCertificateValidator.Validate(result.Ca, "", DateTimeOffset.UtcNow);
        Assert.Equal(result.Ca.Sha256, ca.Sha256);

        // The rendered configuration is accepted by our own parser end to end.
        var conf = WireGuardConfigWriter.Render(result.Vpn, keys, result.Vpn.EndpointFallback);
        Assert.Contains($"Address = {result.Vpn.TunnelIPv4}/32", conf, StringComparison.Ordinal);

        var device = await _client.GetDeviceAsync(result.Token, default);
        Assert.True(device.IsActive);
        Assert.Equal(result.DeviceId, device.DeviceId);
        Assert.False(device.ViaVpn);          // the test client is not inside a tunnel; the server must say so
        Assert.Equal(result.Vpn.TunnelIPv4.ToString(), device.VpnIp);

        var bundle = await _client.GetVpnAsync(result.Token, default);
        Assert.Equal(result.Vpn.Fingerprint(), bundle.Vpn.Fingerprint());
        Assert.NotNull(bundle.Ca);
    }

    [Fact]
    public async Task Each_device_gets_its_own_key_and_address_and_keys_cannot_be_reused()
    {
        using var a = WireGuardKeys.Generate();
        using var b = WireGuardKeys.Generate();
        var ra = await _client.EnrollAsync(_info.Code, a.PublicKey, "A", Uid(), default);
        var rb = await _client.EnrollAsync(_info.Code, b.PublicKey, "B", Uid(), default);
        Assert.NotEqual(ra.Vpn.TunnelIPv4, rb.Vpn.TunnelIPv4);
        Assert.NotEqual(ra.Token, rb.Token);
        Assert.NotEqual(ra.Vpn.PresharedKey, rb.Vpn.PresharedKey);

        var e = await Assert.ThrowsAsync<ApiException>(() => _client.EnrollAsync(_info.Code, a.PublicKey, "A again", Uid(), default));
        Assert.Equal(ApiErrorKind.Conflict, e.Kind);
    }

    [Fact]
    public async Task Invalid_token_is_unauthorized()
    {
        var e = await Assert.ThrowsAsync<ApiException>(() => _client.GetDeviceAsync("not-a-real-token-not-a-real-token", default));
        Assert.Equal(ApiErrorKind.Unauthorized, e.Kind);
        e = await Assert.ThrowsAsync<ApiException>(() => _client.GetVpnAsync("not-a-real-token-not-a-real-token", default));
        Assert.Equal(ApiErrorKind.Unauthorized, e.Kind);
    }

    [Fact]
    public async Task Heartbeat_and_rekey_are_accepted()
    {
        using var keys = WireGuardKeys.Generate();
        var r = await _client.EnrollAsync(_info.Code, keys.PublicKey, "HB", Uid(), default);
        var hb = await _client.HeartbeatAsync(r.Token, new HeartbeatReport
        {
            AppVersion = ProductConfig.Version, DeviceUid = Uid(), VpnState = "DOWN", KillSwitchActive = true,
            TunnelAutoStart = true, CaInstalled = true,
        }, default);
        Assert.Equal("active", hb.Status);
        Assert.NotNull(hb.PolicyVersion);

        using var fresh = WireGuardKeys.Generate();
        var rekeyed = await _client.RekeyAsync(r.Token, fresh.PublicKey, default);
        Assert.Equal(r.Vpn.TunnelIPv4, rekeyed.Vpn.TunnelIPv4);   // same address and policy, new key only
    }

    [Fact]
    public async Task Server_records_the_windows_platform()
    {
        using var keys = WireGuardKeys.Generate();
        var r = await _client.EnrollAsync(_info.Code, keys.PublicKey, "Platform check", Uid(), default);
        using var http = new HttpClient { BaseAddress = new Uri(_info.BaseUrl) };
        var login = await http.PostAsJsonAsync("/v1/admin/login", new { username = _info.AdminUser, password = _info.AdminPassword });
        login.EnsureSuccessStatusCode();
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/v1/admin/devices/{r.DeviceId}");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        var detail = await http.SendAsync(req);
        detail.EnsureSuccessStatusCode();
        var json = await detail.Content.ReadAsStringAsync();
        Assert.Contains("\"platform\":\"windows\"", json.Replace(" ", "", StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Server_outage_is_a_transient_network_error()
    {
        using var dead = new FilterPhoneApiClient(new Uri("http://127.0.0.1:9"));
        var e = await Assert.ThrowsAsync<ApiException>(() => dead.GetDeviceAsync("token", default));
        Assert.True(e.Kind is ApiErrorKind.Network or ApiErrorKind.Timeout);
        Assert.True(e.IsTransient);
        Assert.Equal(0, e.Status);
        _ = HttpStatusCode.OK;
    }
}
