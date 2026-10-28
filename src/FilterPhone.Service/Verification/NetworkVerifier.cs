using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FilterPhone.Core.Verification;

namespace FilterPhone.Service.Verification;

/// <summary>
/// Performs the real network probes whose results <see cref="VerificationEvaluator"/> judges. Probes go
/// through the normal Windows routing (i.e. the tunnel) and certificate validation (the machine trust store),
/// exactly like Chrome would. Only fixed public URLs are fetched; nothing about the user is sent.
/// </summary>
internal static class NetworkVerifier
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);

    public static async Task<TlsProbeOutcome> HttpsAsync(Uri url, bool asImage, CancellationToken ct)
    {
        List<string> built = [];
        var trusted = false;
        var sawCertificate = false;
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
                {
                    sawCertificate = cert is not null;
                    if (chain is not null)
                    {
                        built = chain.ChainElements.Select(e => Sha256(e.Certificate)).ToList();
                    }
                    if (built.Count == 0 && cert is not null)
                    {
                        built = [Sha256(cert)];
                    }
                    trusted = errors == SslPolicyErrors.None;
                    return trusted;
                },
            },
        };
        using var http = new HttpClient(handler) { Timeout = Timeout };
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.UserAgent.ParseAdd("FilterPhone-Desktop-Verifier/1.0");
        if (asImage)
        {
            req.Headers.Accept.ParseAdd("image/webp,image/png,image/*;q=0.8");
            req.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "image");
        }
        try
        {
            using var res = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            var header = res.Headers.TryGetValues("x-filterphone", out var v) ? v.FirstOrDefault() : null;
            return new TlsProbeOutcome
            {
                Target = url.Host, Connected = true, PresentedChain = built, BuiltChain = built, TrustedBySystem = trusted,
                HttpStatus = (int)res.StatusCode, ContentType = res.Content.Headers.ContentType?.MediaType, FilterHeader = header,
            };
        }
        catch (HttpRequestException e)
        {
            return new TlsProbeOutcome
            {
                Target = url.Host, Connected = sawCertificate, PresentedChain = built, BuiltChain = built,
                TrustedBySystem = false, Error = e.HttpRequestError.ToString(),
            };
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TlsProbeOutcome { Target = url.Host, Error = "timeout" };
        }
    }

    /// <summary>Plain HTTP request on port 80 (goes through the filtering proxy), like the Android DataProbe.</summary>
    public static async Task<string?> HttpDataAsync(IEnumerable<string> hosts, CancellationToken ct)
    {
        string? first = null;
        foreach (var host in hosts)
        {
            var failure = await ProbeHostAsync(host, ct).ConfigureAwait(false);
            if (failure is null)
            {
                return null;
            }
            first ??= failure;
        }
        return first;
    }

    private static async Task<string?> ProbeHostAsync(string host, CancellationToken ct)
    {
        System.Net.IPAddress[] addrs;
        try
        {
            using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            dnsCts.CancelAfter(TimeSpan.FromSeconds(5));
            addrs = await System.Net.Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, dnsCts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            return "dns";
        }
        if (addrs.Length == 0)
        {
            return "dns";
        }
        if (addrs[0].Equals(System.Net.IPAddress.Any) || System.Net.IPAddress.IsLoopback(addrs[0]))
        {
            return null;    // blocked by the device's DNS policy: traffic still flows, not a failure
        }
        try
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(addrs[0], 80, cts.Token).ConfigureAwait(false);
            var stream = tcp.GetStream();
            var request = Encoding.ASCII.GetBytes(
                $"GET /generate_204 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: FilterPhone-probe\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(request, cts.Token).ConfigureAwait(false);
            using var reader = new StreamReader(stream, Encoding.ASCII);
            var line = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
            return VerificationEvaluator.IsHttpStatusLine(line) ? null : "http:bad";
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return "timeout";
        }
        catch (Exception e) when (e is SocketException or IOException)
        {
            return "connect";
        }
    }

    public static string Sha256(X509Certificate cert) => Convert.ToHexStringLower(SHA256.HashData(cert.GetRawCertData()));
}
