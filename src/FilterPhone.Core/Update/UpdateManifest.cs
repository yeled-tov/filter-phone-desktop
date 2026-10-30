using System.Text.Json;
using System.Text.Json.Serialization;

namespace FilterPhone.Core.Update;

/// <summary>
/// The update feed (a small JSON document served over HTTPS): the newest version, the HTTPS URL of its
/// installer, and the SHA-256 of that installer. Pure and cross-platform so it is unit-tested on every OS.
/// The service downloads the installer, checks the SHA-256, and — before running it — verifies its
/// Authenticode signature against the configured publisher (see the service's UpdateManager).
/// </summary>
public sealed record UpdateManifest(Version Version, Uri Url, string Sha256)
{
    /// <summary>Parses the feed, returning null for anything malformed (a bad feed never triggers an update).</summary>
    public static UpdateManifest? Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > 64 * 1024)
        {
            return null;
        }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            if (!Version.TryParse(Str(r, "version"), out var version)
                || !Uri.TryCreate(Str(r, "url"), UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            {
                return null;
            }
            var sha = Str(r, "sha256").ToLowerInvariant();
            return sha.Length == 64 && sha.All(Uri.IsHexDigit) ? new UpdateManifest(version, url, sha) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>True when this feed offers a strictly newer version than <paramref name="currentVersion"/>.</summary>
    public bool IsNewerThan(string currentVersion) =>
        Version.TryParse((currentVersion ?? string.Empty).Split('-', '+')[0], out var current) && Version > current;

    private static string Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? string.Empty : string.Empty;
}

/// <summary>The automatic-update state the UI shows (service: UpdateManager).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<UpdateState>))]
public enum UpdateState
{
    Unknown,
    Disabled,       // no feed configured
    UpToDate,
    Checking,
    Downloading,
    Available,      // a newer version exists but cannot be installed automatically (unsigned build); download from the site
    Installing,
    Error,
}
