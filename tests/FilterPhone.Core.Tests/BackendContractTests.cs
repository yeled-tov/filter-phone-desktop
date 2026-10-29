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
            AppVersion = ProductConfig.Version,
            DeviceUid = Uid(),
            VpnState = "DOWN",
            KillSwitchActive = true,
            TunnelAutoStart = true,
            CaInstalled = true,
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

    private async Task<HttpClient> AdminAsync()
    {
        var http = new HttpClient { BaseAddress = new Uri(_info.BaseUrl) };
        var login = await http.PostAsJsonAsync("/v1/admin/login", new { username = _info.AdminUser, password = _info.AdminPassword });
        login.EnsureSuccessStatusCode();
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
        http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    /// <summary>
    /// The computers tab (server: api/removal.py, DeviceSettings.desktop). Against a server that has it, the
    /// dashboard's controls reach the PC and a removal code issued by the dashboard verifies on the PC with the
    /// key the server sent. Against an older server, the PC must see no controls and no key, so it neither
    /// relaxes anything nor ever requires a code that could not be issued.
    /// </summary>
    [Fact]
    public async Task Dashboard_controls_and_removal_codes_round_trip_or_are_absent_on_an_older_server()
    {
        using var keys = WireGuardKeys.Generate();
        var r = await _client.EnrollAsync(_info.Code, keys.PublicKey, "Removal check", Uid(), default);
        var report = new HeartbeatReport
        {
            AppVersion = ProductConfig.Version,
            DeviceUid = Uid(),
            VpnState = "UP",
            WantRemovalKey = true,
            Windows = new WindowsReport("Protected", "Professional", "22631", null,
                Status.Layers.All.ToDictionary(l => l, _ => "ok")),
        };
        var hb = await _client.HeartbeatAsync(r.Token, report, default);
        using var admin = await AdminAsync();
        var issue = await admin.PostAsync($"/v1/admin/devices/{r.DeviceId}/removal-code", null);
        if (hb.Controls is null)
        {
            Assert.Null(hb.RemovalKey);
            Assert.False(issue.IsSuccessStatusCode);
            return;
        }

        Assert.Equal(new DesktopControls(true, true), hb.Controls);
        Assert.NotNull(hb.RemovalKey);
        issue.EnsureSuccessStatusCode();
        var code = (await issue.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString();
        Assert.True(Removal.RemovalCode.Verify(hb.RemovalKey, r.DeviceId, code, DateTimeOffset.UtcNow));
        Assert.False(Removal.RemovalCode.Verify(hb.RemovalKey, r.DeviceId + 1, code, DateTimeOffset.UtcNow));

        var patch = await admin.PatchAsJsonAsync($"/v1/admin/devices/{r.DeviceId}", new { desktop = new { block_store = false } });
        patch.EnsureSuccessStatusCode();
        var after = await _client.HeartbeatAsync(r.Token, report with { WantRemovalKey = false }, default);
        Assert.Equal(new DesktopControls(ChromeOnly: true, BlockStore: false), after.Controls);
        Assert.Null(after.RemovalKey);                     // sent only when the PC asks for it

        var detail = await admin.GetStringAsync($"/v1/admin/devices/{r.DeviceId}");
        Assert.DoesNotContain(hb.RemovalKey!, detail, StringComparison.Ordinal);   // the dashboard never shows the key
        Assert.Contains("\"store_block\":\"ok\"", detail.Replace(" ", "", StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pc_registers_waits_and_after_approval_gets_its_vpn_and_ca()
    {
        var catalog = await _client.GetCatalogAsync(default);
        Assert.Equal([1, 2, 3], catalog.Levels.Select(l => l.Level));
        var option = catalog.ForPc.First(o => o.Popular);

        using var keys = WireGuardKeys.Generate();
        var reg = await _client.RegisterAsync(new RegistrationForm("בדיקת הרשמה", "050-7654321", "", 2, [option.Id], "", "מחשב בדיקה"),
            keys.PublicKey, Uid(), default);
        Assert.Equal("pending", reg.Status);
        Assert.Equal("pending", (await _client.GetDeviceAsync(reg.Token, default)).Status);
        await Assert.ThrowsAsync<ApiException>(() => _client.GetVpnAsync(reg.Token, default));   // nothing before approval

        using var admin = await AdminAsync();
        var requests = await admin.GetFromJsonAsync<JsonElement>("/v1/admin/requests");
        var request = requests.EnumerateArray().Single(r => r.GetProperty("device_id").GetInt32() == reg.DeviceId);
        Assert.Equal("windows", request.GetProperty("platform").GetString());
        var approve = await admin.PostAsJsonAsync($"/v1/admin/requests/{request.GetProperty("id").GetInt32()}/approve",
            new { level = 2, options = new[] { option.Id }, payment = "paid" });
        approve.EnsureSuccessStatusCode();

        var device = await _client.GetDeviceAsync(reg.Token, default);
        Assert.True(device.IsActive);
        var bundle = await _client.GetVpnAsync(reg.Token, default);
        Assert.NotNull(bundle.Ca);
        CaCertificateValidator.Validate(bundle.Ca!, "", DateTimeOffset.UtcNow);
        Assert.StartsWith("10.8.0.", bundle.Vpn.TunnelIPv4.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pending_registration_can_be_withdrawn()
    {
        using var keys = WireGuardKeys.Generate();
        var reg = await _client.RegisterAsync(new RegistrationForm("ביטול בקשה", "050-7654322", "", 1, [], "", ""),
            keys.PublicKey, Uid(), default);
        await _client.CancelRegistrationAsync(reg.Token, default);
        var e = await Assert.ThrowsAsync<ApiException>(() => _client.GetDeviceAsync(reg.Token, default));
        Assert.Equal(ApiErrorKind.Unauthorized, e.Kind);
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
