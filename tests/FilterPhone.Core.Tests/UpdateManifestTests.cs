using FilterPhone.Core.Update;

namespace FilterPhone.Core.Tests;

public class UpdateManifestTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static string Json(string version, string url, string sha) =>
        $"{{\"version\": \"{version}\", \"url\": \"{url}\", \"sha256\": \"{sha}\"}}";

    [Fact]
    public void Parses_a_valid_feed()
    {
        var m = UpdateManifest.Parse(Json("1.4.0", "https://example.com/setup.exe", Sha));
        Assert.NotNull(m);
        Assert.Equal(new Version(1, 4, 0), m!.Version);
        Assert.Equal("https://example.com/setup.exe", m.Url.ToString());
        Assert.Equal(Sha, m.Sha256);
    }

    [Theory]
    [InlineData("1.4.0", "http://example.com/setup.exe")]      // not https
    [InlineData("1.4.0", "ftp://example.com/setup.exe")]
    [InlineData("not-a-version", "https://example.com/s.exe")]
    public void Rejects_bad_version_or_non_https(string version, string url) =>
        Assert.Null(UpdateManifest.Parse(Json(version, url, Sha)));

    [Theory]
    [InlineData("tooshort")]
    [InlineData("zzzz56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00")]   // non-hex
    public void Rejects_a_bad_hash(string sha) =>
        Assert.Null(UpdateManifest.Parse(Json("1.4.0", "https://example.com/s.exe", sha)));

    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("\"a string\"")]
    public void Rejects_malformed_json(string json) => Assert.Null(UpdateManifest.Parse(json));

    [Theory]
    [InlineData("1.4.0", "0.9.0", true)]
    [InlineData("1.4.0", "0.9.0-ci.12", true)]     // pre-release suffix on the current version
    [InlineData("0.9.0", "0.9.0", false)]          // same
    [InlineData("0.8.0", "0.9.0", false)]          // older
    public void Compares_against_the_current_version(string feed, string current, bool newer)
    {
        var m = UpdateManifest.Parse(Json(feed, "https://example.com/s.exe", Sha));
        Assert.NotNull(m);
        Assert.Equal(newer, m!.IsNewerThan(current));
    }
}
