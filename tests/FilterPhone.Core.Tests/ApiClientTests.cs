using System.Net;
using System.Text;
using System.Text.Json;
using FilterPhone.Core.Api;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

internal sealed class FakeHandler(Func<HttpRequestMessage, string?, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<(HttpRequestMessage Request, string? Body)> Calls { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        Calls.Add((request, body));
        return respond(request, body);
    }

    public static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}

public class ApiClientTests
{
    private static readonly Uri Base = new("https://api.filterphone.com");
    private const string CaPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    private static string EnrollResponse(string vpn) =>
        "{\"device_id\": 7, \"token\": \"" + new string('t', 43) + "\", \"status\": \"active\", \"level\": 2, " +
        "\"level_name\": \"בינוני\", \"vpn\": " + vpn + ", \"ca\": {\"pem\": " + JsonSerializer.Serialize(CaPem) +
        ", \"sha256\": \"ABCDEF\", \"name\": \"FilterPhone CA\"}}";

    [Fact]
    public async Task Enroll_sends_only_public_metadata_to_the_verified_route()
    {
        var handler = new FakeHandler((_, _) => FakeHandler.Json(HttpStatusCode.Created, EnrollResponse(TestData.VpnJson())));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        using var keys = WireGuardKeys.Generate();

        var result = await client.EnrollAsync(" ABCDE-FGHJK ", keys.PublicKey, "מחשב Windows", "0123456789abcdef0123456789abcdef", default);

        var (req, body) = Assert.Single(handler.Calls);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("/v1/enroll", req.RequestUri!.AbsolutePath);
        Assert.Null(req.Headers.Authorization);
        using var doc = JsonDocument.Parse(body!);
        var o = doc.RootElement;
        Assert.Equal("ABCDE-FGHJK", o.GetProperty("code").GetString());
        Assert.Equal(keys.PublicKey, o.GetProperty("public_key").GetString());
        Assert.Equal("windows", o.GetProperty("platform").GetString());
        Assert.Equal("מחשב Windows", o.GetProperty("name").GetString());
        Assert.Equal("0123456789abcdef0123456789abcdef", o.GetProperty("device_uid").GetString());
        Assert.DoesNotContain(keys.PrivateKeyBase64(), body!, StringComparison.Ordinal);
        Assert.Equal(6, o.EnumerateObject().Count()); // code, public_key, name, platform, app_version, device_uid

        Assert.Equal(7, result.DeviceId);
        Assert.Equal(2, result.Level);
        Assert.Equal("abcdef", result.Ca.Sha256);
        Assert.Equal(IPAddress.Parse("10.8.0.10"), result.Vpn.TunnelIPv4);
        Assert.DoesNotContain(result.Token, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("\"ca\"", result.VpnJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transfer_codes_use_the_transfer_route()
    {
        var handler = new FakeHandler((_, _) => FakeHandler.Json(HttpStatusCode.Created, EnrollResponse(TestData.VpnJson())));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        using var keys = WireGuardKeys.Generate();
        await client.EnrollAsync("FPT-abcdefghijklmnop_-123", keys.PublicKey, "pc", "", default);
        var (req, body) = Assert.Single(handler.Calls);
        Assert.Equal("/v1/transfer", req.RequestUri!.AbsolutePath);
        Assert.Contains("\"token\":\"FPT-abcdefghijklmnop_-123\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("device_uid", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_code_surfaces_the_server_message()
    {
        var handler = new FakeHandler((_, _) =>
            FakeHandler.Json(HttpStatusCode.Forbidden, "{\"error\": \"קוד ההפעלה לא תקין או שפג תוקפו\"}"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        using var keys = WireGuardKeys.Generate();
        var e = await Assert.ThrowsAsync<ApiException>(() => client.EnrollAsync("WRONG-CODE1", keys.PublicKey, "pc", "", default));
        Assert.Equal(ApiErrorKind.Forbidden, e.Kind);
        Assert.Equal(403, e.Status);
        Assert.Equal("קוד ההפעלה לא תקין או שפג תוקפו", e.ServerMessage);
        Assert.False(e.IsTransient);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("ABCDE FGHJK")]
    [InlineData("ABCDE-FG\nHJK")]
    [InlineData("<script>")]
    public async Task Malformed_codes_are_rejected_before_any_request(string code)
    {
        var handler = new FakeHandler((_, _) => throw new InvalidOperationException("must not be called"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        using var keys = WireGuardKeys.Generate();
        await Assert.ThrowsAsync<ArgumentException>(() => client.EnrollAsync(code, keys.PublicKey, "pc", "", default));
        Assert.Empty(handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, ApiErrorKind.Unauthorized, false)]
    [InlineData(HttpStatusCode.TooManyRequests, ApiErrorKind.RateLimited, true)]
    [InlineData(HttpStatusCode.ServiceUnavailable, ApiErrorKind.ServerError, true)]
    [InlineData(HttpStatusCode.Conflict, ApiErrorKind.Conflict, false)]
    [InlineData(HttpStatusCode.Found, ApiErrorKind.InvalidResponse, false)]
    public async Task Http_errors_map_to_kinds(HttpStatusCode code, ApiErrorKind kind, bool transient)
    {
        var handler = new FakeHandler((_, _) => new HttpResponseMessage(code) { Content = new StringContent("not json") });
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var e = await Assert.ThrowsAsync<ApiException>(() => client.GetDeviceAsync("token-token-token-token", default));
        Assert.Equal(kind, e.Kind);
        Assert.Equal(transient, e.IsTransient);
        Assert.Null(e.ServerMessage);
    }

    [Fact]
    public async Task Network_failure_is_transient()
    {
        var handler = new FakeHandler((_, _) => throw new HttpRequestException("connection refused"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var e = await Assert.ThrowsAsync<ApiException>(() => client.GetDeviceAsync("tok", default));
        Assert.Equal(ApiErrorKind.Network, e.Kind);
        Assert.True(e.IsTransient);
    }

    [Fact]
    public async Task Timeout_is_reported_as_timeout()
    {
        var handler = new FakeHandler((_, _) => throw new TaskCanceledException("timeout"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var e = await Assert.ThrowsAsync<ApiException>(() => client.GetVpnAsync("tok", default));
        Assert.Equal(ApiErrorKind.Timeout, e.Kind);
    }

    [Fact]
    public async Task Incomplete_vpn_configuration_is_an_invalid_response()
    {
        var handler = new FakeHandler((_, _) =>
            FakeHandler.Json(HttpStatusCode.OK, TestData.VpnJson(allowed: "[\"0.0.0.0/0\"]")));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var e = await Assert.ThrowsAsync<ApiException>(() => client.GetVpnAsync("tok", default));
        Assert.Equal(ApiErrorKind.InvalidResponse, e.Kind);
        Assert.IsType<VpnConfigException>(e.InnerException);
    }

    [Fact]
    public async Task Device_status_reads_via_vpn_and_support_number()
    {
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal("Bearer secret-token", req.Headers.Authorization!.ToString());
            return FakeHandler.Json(HttpStatusCode.OK, """
                {"device_id": 3, "name": "pc", "status": "active", "level": 1, "level_name": "מחמיר", "server_time": 1700000000,
                 "message": "", "vpn_ip": "10.8.0.10", "via_vpn": true, "heartbeat_interval_s": 900,
                 "support": {"unread": 0, "whatsapp": "972500000000"}}
                """);
        });
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var d = await client.GetDeviceAsync("secret-token", default);
        Assert.True(d.IsActive);
        Assert.True(d.ViaVpn);
        Assert.Equal("10.8.0.10", d.VpnIp);
        Assert.Equal(900, d.HeartbeatIntervalSeconds);
        Assert.Equal("972500000000", d.SupportWhatsApp);
    }

    [Fact]
    public async Task Heartbeat_sends_only_sanitised_fields()
    {
        var handler = new FakeHandler((_, _) => FakeHandler.Json(HttpStatusCode.OK,
            "{\"server_time\": 1, \"status\": \"active\", \"policy_version\": 4, \"interval_s\": 900, \"message\": \"\"}"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        var r = await client.HeartbeatAsync("tok", new HeartbeatReport
        {
            AppVersion = "1.0.0", DeviceUid = "0123456789abcdef", VpnState = "UP", HandshakeAgeSeconds = 12,
            KillSwitchActive = true, TunnelAutoStart = true, CaInstalled = true, PolicyVersion = 4, DataOk = true,
            VpnError = new string('x', 300),
        }, default);
        Assert.Equal(4, r.PolicyVersion);
        var body = handler.Calls[0].Body!;
        using var doc = JsonDocument.Parse(body);
        var vpn = doc.RootElement.GetProperty("vpn");
        Assert.Equal("UP", vpn.GetProperty("state").GetString());
        Assert.True(vpn.GetProperty("lockdown").GetBoolean());
        Assert.True(vpn.GetProperty("always_on").GetBoolean());
        Assert.Equal(80, vpn.GetProperty("error").GetString()!.Length);
        Assert.True(doc.RootElement.GetProperty("ca_installed").GetBoolean());
        Assert.Equal("/v1/device/heartbeat", handler.Calls[0].Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task Rekey_validates_the_new_public_key()
    {
        var handler = new FakeHandler((_, _) => FakeHandler.Json(HttpStatusCode.OK, TestData.VpnJson()));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        await Assert.ThrowsAsync<ArgumentException>(() => client.RekeyAsync("tok", "bad", default));
        using var keys = WireGuardKeys.Generate();
        var bundle = await client.RekeyAsync("tok", keys.PublicKey, default);
        Assert.Equal("/v1/device/rekey", handler.Calls[0].Request.RequestUri!.AbsolutePath);
        Assert.Null(bundle.Ca);
    }
}
