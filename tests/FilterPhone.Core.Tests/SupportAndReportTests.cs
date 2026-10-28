using FilterPhone.Core.Diagnostics;
using FilterPhone.Core.Status;
using FilterPhone.Core.Support;

namespace FilterPhone.Core.Tests;

public class SupportAndReportTests
{
    private static ProtectionSnapshot Snapshot() => new()
    {
        Overall = OverallState.Reconnecting,
        Checks = Layers.All.ToDictionary(l => l, LayerCheck.Unknown),
        DeviceId = 42,
        DeviceName = "מחשב הבית",
        Version = "1.2.3",
        WindowsEdition = "Professional",
        WindowsBuild = "22631",
    };

    [Fact]
    public void Message_has_device_and_state_but_nothing_sensitive()
    {
        var m = SupportMessage.Compose(Snapshot());
        Assert.Contains("מכשיר #42 · מחשב הבית", m, StringComparison.Ordinal);
        Assert.Contains("1.2.3", m, StringComparison.Ordinal);
        Assert.Contains("מתחבר מחדש", m, StringComparison.Ordinal);
        Assert.DoesNotContain("token", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Links_are_encoded()
    {
        var wa = SupportMessage.WhatsAppDesktopUri("972527186881", "שלום & ?x=1\nשורה");
        Assert.Equal("whatsapp", wa.Scheme);
        Assert.Contains("phone=972527186881", wa.OriginalString, StringComparison.Ordinal);
        Assert.DoesNotContain("&x=1", wa.OriginalString, StringComparison.Ordinal);
        Assert.Contains("%0A", wa.OriginalString, StringComparison.Ordinal);
        Assert.StartsWith("https://wa.me/972527186881?text=", SupportMessage.WhatsAppWebUri("972527186881", "a").OriginalString, StringComparison.Ordinal);
        var mail = SupportMessage.MailtoUri("support@example.org", "נושא", "גוף");
        Assert.StartsWith("mailto:support@example.org?subject=", mail.OriginalString, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => SupportMessage.WhatsAppDesktopUri("+97252", "x"));
        Assert.Throws<ArgumentException>(() => SupportMessage.MailtoUri("", "s", "b"));
        Assert.Throws<ArgumentException>(() => SupportMessage.MailtoUri("a@b.c?cc=evil@x.y", "s", "b"));
    }

    [Fact]
    public void Diagnostic_report_is_redacted()
    {
        var events = new[] { "enrol failed for code ABCDE-FGHJK", "PrivateKey = SECRETSECRET", "ok" };
        var r = DiagnosticReport.Build(Snapshot(), events, DateTimeOffset.UtcNow);
        Assert.Contains("App version: 1.2.3", r, StringComparison.Ordinal);
        Assert.Contains("build 22631", r, StringComparison.Ordinal);
        Assert.Contains("kill_switch", r, StringComparison.Ordinal);
        Assert.DoesNotContain("ABCDE-FGHJK", r, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRETSECRET", r, StringComparison.Ordinal);
    }
}

public class ProductConfigTests
{
    [Fact]
    public void Defaults_are_the_verified_values()
    {
        var c = ProductConfig.Current;
        Assert.Equal(new Uri("https://api.filterphone.com"), c.ApiBaseUrl);
        Assert.Equal("972527186881", c.SupportWhatsApp);
        Assert.Equal("development", c.Channel);
    }

    [Theory]
    [InlineData("http://api.filterphone.com", "972527186881", "", "")]
    [InlineData("https://api.filterphone.com", "+972", "", "")]
    [InlineData("https://api.filterphone.com", "972527186881", "not-an-email", "")]
    [InlineData("https://api.filterphone.com", "972527186881", "", "abc")]
    public void Invalid_settings_fail_the_build_configuration(string api, string wa, string mail, string pin) =>
        Assert.Throws<InvalidOperationException>(() => ProductConfig.Create(api, wa, mail, pin, ""));

    [Fact]
    public void Loopback_http_is_allowed_for_contract_tests() =>
        Assert.Equal("http", ProductConfig.Create("http://127.0.0.1:8765", "", "", "", "").ApiBaseUrl.Scheme);
}
