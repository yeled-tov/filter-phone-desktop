using FilterPhone.Core.Util;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

public class BackoffTests
{
    [Fact]
    public void Grows_is_bounded_and_resets()
    {
        var b = new Backoff(random: () => 0.5);
        var now = DateTimeOffset.UnixEpoch;
        var delays = Enumerable.Range(0, 20).Select(_ => b.Failed(now)).ToList();
        Assert.Equal(TimeSpan.FromSeconds(5), delays[0]);
        Assert.True(delays.Zip(delays.Skip(1)).All(p => p.Second >= p.First));
        Assert.Equal(TimeSpan.FromMinutes(15), delays[^1]);
        Assert.False(b.CanAttempt(now));
        Assert.True(b.CanAttempt(now + TimeSpan.FromMinutes(16)));
        b.Succeeded();
        Assert.True(b.CanAttempt(now));
        Assert.Equal(TimeSpan.FromSeconds(5), b.Failed(now));
    }

    [Fact]
    public void Never_returns_less_than_one_second() =>
        Assert.True(new Backoff([TimeSpan.FromMilliseconds(1)], () => 0).Failed(DateTimeOffset.UtcNow) >= TimeSpan.FromSeconds(1));
}

public class RedactorTests
{
    [Fact]
    public void Removes_keys_tokens_codes_pem_and_personal_data()
    {
        using var keys = WireGuardKeys.Generate();
        var token = "Q2xhdWRlX2RvZXNfbm90X2xvZ190b2tlbnNfZXZlcl8x"; // 43 chars like token_urlsafe(32)
        var text = string.Join('\n',
            $"PrivateKey = {keys.PrivateKeyBase64()}",
            $"public {keys.PublicKey}",
            $"Authorization: Bearer {token}",
            $"token={token}",
            "code ABCDE-FGHJK and FPT-xyz_123",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "mail me@example.com phone 050-123-4567 or +972501234567",
            @"path C:\Users\Moshe\AppData\Local\x");
        var r = Redactor.Redact(text);
        Assert.DoesNotContain(keys.PrivateKeyBase64(), r, StringComparison.Ordinal);
        Assert.DoesNotContain(keys.PublicKey, r, StringComparison.Ordinal);
        Assert.DoesNotContain(token, r, StringComparison.Ordinal);
        Assert.DoesNotContain("ABCDE-FGHJK", r, StringComparison.Ordinal);
        Assert.DoesNotContain("FPT-xyz", r, StringComparison.Ordinal);
        Assert.DoesNotContain("MIIB", r, StringComparison.Ordinal);
        Assert.DoesNotContain("me@example.com", r, StringComparison.Ordinal);
        Assert.DoesNotContain("123-4567", r, StringComparison.Ordinal);
        Assert.DoesNotContain("501234567", r, StringComparison.Ordinal);
        Assert.DoesNotContain("Moshe", r, StringComparison.Ordinal);
        Assert.Contains("PrivateKey = <redacted>", r, StringComparison.Ordinal);
    }

    [Fact]
    public void Leaves_ordinary_diagnostics_alone()
    {
        const string text = "tunnel UP handshake 12s ago, build 22631, state Protected";
        Assert.Equal(text, Redactor.Redact(text));
    }
}
