using System.Reflection;
using System.Text.RegularExpressions;

namespace FilterPhone.Core;

/// <summary>
/// Build-time product settings embedded as assembly metadata (see FilterPhone.Core.csproj).
/// Nothing here is a secret: the API URL and the support contacts are public.
/// </summary>
public sealed partial class ProductConfig
{
    public required Uri ApiBaseUrl { get; init; }

    /// <summary>WhatsApp number in international format without "+" (e.g. 9725XXXXXXXX).</summary>
    public required string SupportWhatsApp { get; init; }

    /// <summary>Empty when the owner has not configured a verified support mailbox.</summary>
    public required string SupportEmail { get; init; }

    /// <summary>Optional SHA-256 pin (hex) of the filtering CA. Empty = trust-on-enrolment from the authenticated API.</summary>
    public required string ExpectedCaSha256 { get; init; }

    /// <summary>"production" for tagged releases, "development" otherwise.</summary>
    public required string Channel { get; init; }

    public const string ProductName = "FilterPhone Desktop";
    public const string Platform = "windows";
    public const string TunnelName = "FilterPhone";

    public static ProductConfig Current { get; } = FromAssembly(typeof(ProductConfig).Assembly);

    public static string Version =>
        typeof(ProductConfig).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0] ?? "0.0.0";

    internal static ProductConfig FromAssembly(Assembly assembly)
    {
        var meta = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .ToDictionary(a => a.Key, a => a.Value ?? string.Empty, StringComparer.Ordinal);
        string Get(string key) => meta.TryGetValue("FilterPhone." + key, out var v) ? v.Trim() : string.Empty;
        return Create(Get("ApiBaseUrl"), Get("SupportWhatsApp"), Get("SupportEmail"), Get("ExpectedCaSha256"),
            Get("Channel"));
    }

    public static ProductConfig Create(string apiBaseUrl, string whatsApp, string email, string caPin, string channel)
    {
        if (!Uri.TryCreate(apiBaseUrl, UriKind.Absolute, out var api) || api.Scheme != Uri.UriSchemeHttps
            && !(api.IsLoopback && api.Scheme == Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException("The API base URL must be an absolute https:// URL.");
        }
        if (whatsApp.Length > 0 && !WhatsAppNumber().IsMatch(whatsApp))
        {
            throw new InvalidOperationException("The support WhatsApp number must be digits in international format.");
        }
        if (email.Length > 0 && !Email().IsMatch(email))
        {
            throw new InvalidOperationException("The support e-mail address is not valid.");
        }
        caPin = caPin.Replace(":", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
        if (caPin.Length > 0 && !Sha256Hex().IsMatch(caPin))
        {
            throw new InvalidOperationException("The CA pin must be a SHA-256 hex digest.");
        }
        return new ProductConfig
        {
            ApiBaseUrl = api,
            SupportWhatsApp = whatsApp,
            SupportEmail = email,
            ExpectedCaSha256 = caPin,
            Channel = channel.Length == 0 ? "development" : channel,
        };
    }

    [GeneratedRegex("^[1-9][0-9]{7,14}$")]
    private static partial Regex WhatsAppNumber();

    [GeneratedRegex(@"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")]
    private static partial Regex Email();

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Hex();
}
