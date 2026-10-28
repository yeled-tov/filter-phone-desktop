using FilterPhone.Core.Status;
using FilterPhone.Core.Verification;

namespace FilterPhone.Core.Tests;

public class VerificationTests
{
    private const string Ca = "aa11";
    private const string PublicRoot = "bb22";

    private static TlsProbeOutcome Probe(string root, bool trusted = true, int? status = 200, string? ct = "text/html",
        string? header = null) => new()
    {
        Target = "t", Connected = true, PresentedChain = ["leaf", root], BuiltChain = ["leaf", root],
        TrustedBySystem = trusted, HttpStatus = status, ContentType = ct, FilterHeader = header,
    };

    [Fact]
    public void Interception_requires_the_filtering_ca()
    {
        Assert.Equal(new ProbeVerdict(CheckState.Ok, "intercepted"), VerificationEvaluator.Interception([Probe(Ca), Probe(Ca)], Ca));
        Assert.Equal("intercepted_partial", VerificationEvaluator.Interception([Probe(Ca), Probe(PublicRoot)], Ca).Code);
        Assert.Equal(new ProbeVerdict(CheckState.Failed, "not_intercepted"), VerificationEvaluator.Interception([Probe(PublicRoot)], Ca));
        Assert.Equal("ca_not_trusted", VerificationEvaluator.Interception([Probe(Ca, trusted: false)], Ca).Code);
        Assert.Equal("unreachable", VerificationEvaluator.Interception([new TlsProbeOutcome { Target = "x" }], Ca).Code);
        Assert.Equal("no_ca", VerificationEvaluator.Interception([Probe(Ca)], "").Code);
    }

    [Fact]
    public void Image_path_verdicts()
    {
        Assert.Equal("image_through_filter", VerificationEvaluator.ImagePath(Probe(Ca, ct: "image/png"), Ca).Code);
        Assert.Equal("filter_acted", VerificationEvaluator.ImagePath(Probe(Ca, ct: "image/png", header: "block"), Ca).Code);
        Assert.Equal(CheckState.Failed, VerificationEvaluator.ImagePath(Probe(PublicRoot, ct: "image/png"), Ca).State);
        Assert.Equal("http_502", VerificationEvaluator.ImagePath(Probe(Ca, status: 502, ct: "text/html"), Ca).Code);
        Assert.Equal(CheckState.Failed, VerificationEvaluator.ImagePath(null, Ca).State);
    }

    [Theory]
    [InlineData("HTTP/1.1 204 No Content", true)]
    [InlineData("HTTP/1.1 403 Forbidden", true)]
    [InlineData("HTTP/1.0 302", true)]
    [InlineData("SSH-2.0-OpenSSH", false)]
    [InlineData("HTTP/1.1 999 x", false)]
    [InlineData(null, false)]
    public void Http_status_line(string? line, bool ok) => Assert.Equal(ok, VerificationEvaluator.IsHttpStatusLine(line));
}
