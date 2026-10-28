using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FilterPhone.Core.Trust;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Api;

/// <summary>Resolves the API host. The service substitutes a cache-aware resolver for use while DNS is blocked.</summary>
public delegate ValueTask<IPAddress[]> HostResolver(string host, CancellationToken ct);

/// <summary>
/// Client for the device-facing FilterPhone API. Routes, bodies and responses follow
/// server/filterphone/api/app.py and service.py in yeled-tov/filterphone (verified, not assumed).
/// Authentication: <c>Authorization: Bearer &lt;device token&gt;</c>.
/// </summary>
public sealed partial class FilterPhoneApiClient : IDisposable
{
    public const int MaxResponseBytes = 1_000_000;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private static readonly JsonSerializerOptions BodyOptions = new() { WriteIndented = false };

    private readonly HttpClient _http;
    private readonly Uri _base;

    public FilterPhoneApiClient(Uri baseUrl, HostResolver? resolver = null, HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        _base = baseUrl;
        _http = new HttpClient(handler ?? CreateHandler(resolver), disposeHandler: true)
        {
            Timeout = RequestTimeout,
            MaxResponseContentBufferSize = MaxResponseBytes,
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("FilterPhone-Desktop", ProductConfig.Version));
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public Uri BaseUrl => _base;

    private static SocketsHttpHandler CreateHandler(HostResolver? resolver)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,              // the API never redirects; a redirect is treated as an error
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            UseProxy = false,                       // a user-level proxy must not sit between the service and the API
            UseCookies = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            },
        };
        if (resolver is not null)
        {
            handler.ConnectCallback = async (ctx, ct) =>
            {
                var addresses = await resolver(ctx.DnsEndPoint.Host, ct).ConfigureAwait(false);
                Exception? last = null;
                foreach (var ip in addresses)
                {
                    var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(ip, ctx.DnsEndPoint.Port), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception e) when (e is SocketException or OperationCanceledException)
                    {
                        socket.Dispose();
                        last = e;
                        if (ct.IsCancellationRequested)
                        {
                            throw;
                        }
                    }
                }
                throw last ?? new SocketException((int)SocketError.HostNotFound);
            };
        }
        return handler;
    }

    // ------------------------------------------------------------------ enrolment

    /// <summary>
    /// <c>POST /v1/enroll</c> with an activation code, or <c>POST /v1/transfer</c> for a device-replacement
    /// code (prefix "FPT-", same rule as the Android app). Only the public key and non-identifying metadata are sent.
    /// </summary>
    public async Task<EnrollmentResult> EnrollAsync(string code, string publicKey, string deviceName,
        string deviceUid, CancellationToken ct)
    {
        var trimmed = code.Trim();
        if (!IsPlausibleCode(trimmed))
        {
            throw new ArgumentException("Activation code format is invalid.", nameof(code));
        }
        if (!WireGuardKeys.IsValidKey(publicKey))
        {
            throw new ArgumentException("Public key is invalid.", nameof(publicKey));
        }
        var isTransfer = trimmed.StartsWith("FPT-", StringComparison.OrdinalIgnoreCase);
        var body = new Dictionary<string, object?>
        {
            [isTransfer ? "token" : "code"] = trimmed,
            ["public_key"] = publicKey,
            ["name"] = Clip(deviceName, 60),
            ["platform"] = ProductConfig.Platform,
            ["app_version"] = Clip(ProductConfig.Version, 20),
        };
        if (deviceUid.Length > 0)
        {
            body["device_uid"] = deviceUid;
        }
        using var doc = await SendAsync(HttpMethod.Post, isTransfer ? "/v1/transfer" : "/v1/enroll", null, body, ct)
            .ConfigureAwait(false);
        var root = doc.RootElement;
        var token = Json.String(root, "token");
        if (token.Length is < 20 or > 200)
        {
            throw new ApiException(ApiErrorKind.InvalidResponse, 201, null);
        }
        var (vpn, vpnJson) = ParseVpn(root, "vpn");
        var ca = CaInfo.FromJson(root) ?? throw new ApiException(ApiErrorKind.InvalidResponse, 201, null);
        return new EnrollmentResult(Json.Int(root, "device_id"), token, Json.String(root, "status", "active"),
            Json.Int(root, "level"), Json.String(root, "level_name"), vpn, vpnJson, ca);
    }

    /// <summary>Activation codes: "XXXXX-XXXXX" (6-32 chars per the API); transfer codes: "FPT-" + token.</summary>
    public static bool IsPlausibleCode(string code) =>
        code.Length is >= 6 and <= 80 && CodePattern().IsMatch(code)
        && (code.StartsWith("FPT-", StringComparison.OrdinalIgnoreCase) || code.Length <= 32);

    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex CodePattern();

    // ------------------------------------------------------------------ device

    /// <summary><c>GET /v1/device</c>. <see cref="DeviceInfo.ViaVpn"/> is the server's own observation of the tunnel.</summary>
    public async Task<DeviceInfo> GetDeviceAsync(string token, CancellationToken ct)
    {
        using var doc = await SendAsync(HttpMethod.Get, "/v1/device", token, null, ct).ConfigureAwait(false);
        var r = doc.RootElement;
        var support = r.TryGetProperty("support", out var s) && s.ValueKind == JsonValueKind.Object ? s : default;
        var wa = support.ValueKind == JsonValueKind.Object ? Json.String(support, "whatsapp") : string.Empty;
        return new DeviceInfo(
            Json.Int(r, "device_id"), Json.String(r, "name"), Json.String(r, "status"), Json.Int(r, "level"),
            Json.String(r, "level_name"), Json.String(r, "message"), Json.Bool(r, "via_vpn"),
            r.TryGetProperty("vpn_ip", out var ip) && ip.ValueKind == JsonValueKind.String ? ip.GetString() : null,
            Math.Clamp(Json.Int(r, "heartbeat_interval_s", 900), 300, 86_400), wa, Json.Long(r, "server_time"));
    }

    /// <summary><c>GET /v1/device/vpn</c> — only for an active device (403 otherwise).</summary>
    public async Task<VpnBundle> GetVpnAsync(string token, CancellationToken ct)
    {
        using var doc = await SendAsync(HttpMethod.Get, "/v1/device/vpn", token, null, ct).ConfigureAwait(false);
        var (vpn, json) = ParseVpn(doc.RootElement, null);
        return new VpnBundle(vpn, json, CaInfo.FromJson(doc.RootElement));
    }

    /// <summary><c>POST /v1/device/rekey</c>: replaces this device's WireGuard public key (rate-limited to 3/day).</summary>
    public async Task<VpnBundle> RekeyAsync(string token, string publicKey, CancellationToken ct)
    {
        if (!WireGuardKeys.IsValidKey(publicKey))
        {
            throw new ArgumentException("Public key is invalid.", nameof(publicKey));
        }
        using var doc = await SendAsync(HttpMethod.Post, "/v1/device/rekey", token,
            new Dictionary<string, object?> { ["public_key"] = publicKey }, ct).ConfigureAwait(false);
        var (vpn, json) = ParseVpn(doc.RootElement, null);
        return new VpnBundle(vpn, json, CaInfo.FromJson(doc.RootElement));
    }

    /// <summary><c>POST /v1/device/heartbeat</c>.</summary>
    public async Task<HeartbeatResult> HeartbeatAsync(string token, HeartbeatReport report, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(report);
        using var doc = await SendAsync(HttpMethod.Post, "/v1/device/heartbeat", token, report.ToJsonBody(), ct)
            .ConfigureAwait(false);
        var r = doc.RootElement;
        return new HeartbeatResult(Json.String(r, "status"), Json.NullableInt(r, "policy_version"),
            Math.Clamp(Json.Int(r, "interval_s", 900), 300, 86_400), Json.String(r, "message"));
    }

    // ------------------------------------------------------------------ transport

    private static (VpnSettings, string) ParseVpn(JsonElement root, string? property)
    {
        JsonElement vpnEl;
        if (property is null)
        {
            vpnEl = root;
        }
        else if (!root.TryGetProperty(property, out vpnEl))
        {
            throw new ApiException(ApiErrorKind.InvalidResponse, 200, null);
        }
        try
        {
            var settings = VpnSettings.Parse(vpnEl);
            // Store only the VPN object (without the CA): it is re-validated on every load.
            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms))
            {
                w.WriteStartObject();
                foreach (var p in vpnEl.EnumerateObject())
                {
                    if (p.Name != "ca")
                    {
                        p.WriteTo(w);
                    }
                }
                w.WriteEndObject();
            }
            return (settings, Encoding.UTF8.GetString(ms.ToArray()));
        }
        catch (VpnConfigException e)
        {
            throw new ApiException(ApiErrorKind.InvalidResponse, 200, null, e);
        }
    }

    private async Task<JsonDocument> SendAsync(HttpMethod method, string path, string? token,
        Dictionary<string, object?>? body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, new Uri(_base, path));
        if (token is not null)
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        if (body is not null)
        {
            req.Content = new StringContent(JsonSerializer.Serialize(body, BodyOptions), Encoding.UTF8, "application/json");
        }

        HttpResponseMessage res;
        try
        {
            res = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
        }
        catch (TaskCanceledException e) when (!ct.IsCancellationRequested)
        {
            throw new ApiException(ApiErrorKind.Timeout, 0, null, e);
        }
        catch (HttpRequestException e)
        {
            var kind = e.InnerException is AuthenticationException || e.HttpRequestError == HttpRequestError.SecureConnectionError
                ? ApiErrorKind.Tls
                : ApiErrorKind.Network;
            throw new ApiException(kind, 0, null, e);
        }

        using (res)
        {
            byte[] bytes;
            try
            {
                bytes = await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            }
            catch (HttpRequestException e)
            {
                throw new ApiException(ApiErrorKind.Network, (int)res.StatusCode, null, e);
            }
            JsonDocument? doc = null;
            if (bytes.Length > 0)
            {
                try
                {
                    doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
                }
                catch (JsonException)
                {
                    doc = null;
                }
            }
            var status = (int)res.StatusCode;
            if (status is >= 200 and < 300)
            {
                if (status == 204)
                {
                    doc?.Dispose();
                    return JsonDocument.Parse("{}");
                }
                if (doc is null || doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    doc?.Dispose();
                    throw new ApiException(ApiErrorKind.InvalidResponse, status, null);
                }
                return doc;
            }
            string? message = null;
            if (doc is not null && doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var m = Json.String(doc.RootElement, "error");
                message = m.Length is > 0 and <= 500 ? m : null;
            }
            doc?.Dispose();
            throw new ApiException(ApiException.FromStatus(res.StatusCode), status, message);
        }
    }

    private static string Clip(string s, int max)
    {
        s = s.Trim();
        return s.Length <= max ? s : s[..max];
    }

    public void Dispose() => _http.Dispose();
}
