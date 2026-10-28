using FilterPhone.Core.Status;

namespace FilterPhone.Core.Verification;

/// <summary>What one HTTPS probe observed. Hashes are SHA-256 (hex) of the DER certificates.</summary>
public sealed record TlsProbeOutcome
{
    public required string Target { get; init; }
    public bool Connected { get; init; }
    /// <summary>Certificates the server presented, leaf first.</summary>
    public IReadOnlyList<string> PresentedChain { get; init; } = [];
    /// <summary>Chain Windows built when validating (leaf first); its last element is the trust anchor.</summary>
    public IReadOnlyList<string> BuiltChain { get; init; } = [];
    public bool TrustedBySystem { get; init; }
    public int? HttpStatus { get; init; }
    public string? ContentType { get; init; }
    /// <summary>The proxy's <c>x-filterphone</c> header (set when it replaced, blocked or filtered a response).</summary>
    public string? FilterHeader { get; init; }
    public string? Error { get; init; }
}

public sealed record ProbeVerdict(CheckState State, string Code);

/// <summary>
/// Pure decision logic for the filtering checks (tested without a network).
/// Interception is proven when a public HTTPS site is presented with a certificate issued by the device's
/// FilterPhone CA, i.e. the TLS session terminates in the server's filtering proxy (server: fp-proxy,
/// mitmproxy in transparent mode behind iptables REDIRECT of tunnel ports 80/443).
/// </summary>
public static class VerificationEvaluator
{
    public static ProbeVerdict Interception(IReadOnlyList<TlsProbeOutcome> probes, string caSha256)
    {
        ArgumentNullException.ThrowIfNull(probes);
        if (string.IsNullOrEmpty(caSha256))
        {
            return new ProbeVerdict(CheckState.Failed, "no_ca");
        }
        var connected = probes.Where(p => p.Connected).ToList();
        if (connected.Count == 0)
        {
            return new ProbeVerdict(CheckState.Failed, "unreachable");
        }
        var intercepted = connected.Where(p => IsIntercepted(p, caSha256)).ToList();
        if (intercepted.Count == 0)
        {
            // Reached the internet with a certificate that does not come from the filtering proxy:
            // traffic is not passing through the filter.
            return new ProbeVerdict(CheckState.Failed, "not_intercepted");
        }
        if (intercepted.Any(p => !p.TrustedBySystem))
        {
            return new ProbeVerdict(CheckState.Failed, "ca_not_trusted");
        }
        return new ProbeVerdict(CheckState.Ok, intercepted.Count == connected.Count ? "intercepted" : "intercepted_partial");
    }

    public static ProbeVerdict ImagePath(TlsProbeOutcome? probe, string caSha256)
    {
        if (probe is null || !probe.Connected)
        {
            return new ProbeVerdict(CheckState.Failed, "unreachable");
        }
        if (!IsIntercepted(probe, caSha256))
        {
            return new ProbeVerdict(CheckState.Failed, "image_not_through_filter");
        }
        if (!probe.TrustedBySystem)
        {
            return new ProbeVerdict(CheckState.Failed, "ca_not_trusted");
        }
        if (probe.FilterHeader is { Length: > 0 })
        {
            return new ProbeVerdict(CheckState.Ok, "filter_acted");
        }
        if (probe.HttpStatus is >= 200 and < 300 && probe.ContentType?.StartsWith("image/", StringComparison.OrdinalIgnoreCase) == true)
        {
            return new ProbeVerdict(CheckState.Ok, "image_through_filter");
        }
        return new ProbeVerdict(CheckState.Failed, probe.HttpStatus is int s ? $"http_{s}" : "no_response");
    }

    /// <summary>Mirrors Android DataProbe.parseStatus: any HTTP status line means traffic flows.</summary>
    public static bool IsHttpStatusLine(string? line)
    {
        var parts = line?.Trim().Split(' ');
        return parts is { Length: >= 2 } && parts[0].StartsWith("HTTP/", StringComparison.Ordinal)
            && int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var code)
            && code is >= 100 and <= 599;
    }

    private static bool IsIntercepted(TlsProbeOutcome p, string caSha256) =>
        p.PresentedChain.Contains(caSha256, StringComparer.OrdinalIgnoreCase)
        || (p.BuiltChain.Count > 0 && string.Equals(p.BuiltChain[^1], caSha256, StringComparison.OrdinalIgnoreCase));
}

/// <summary>The fixed probe targets. Public, stable, not on the proxy pass-through list.</summary>
public static class ProbeTargets
{
    public static readonly Uri[] Interception =
    [
        new("https://www.google.com/generate_204"),
        new("https://www.wikipedia.org/"),
    ];

    /// <summary>A small, neutral logo image.</summary>
    public static readonly Uri Image = new("https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png");

    /// <summary>Plain-HTTP traffic check, same targets as the Android DataProbe.</summary>
    public static readonly string[] HttpData = ["connectivitycheck.gstatic.com", "filterphone.com"];
}
