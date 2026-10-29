using FilterPhone.Core.Removal;

namespace FilterPhone.Core.Tests;

public class RemovalCodeTests
{
    // The same vector is checked on the server (server/tests/test_windows.py).
    private const string Key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    private static DateTimeOffset Day(long day, int seconds = 100) => DateTimeOffset.FromUnixTimeSeconds(day * 86_400 + seconds);

    [Fact]
    public void Matches_the_server_vector()
    {
        Assert.Equal("EEHMJ-S2M43", RemovalCode.Compute(Key, 42, 20_000));
        Assert.Equal("EEHMJ-S2M43", RemovalCode.Normalize("eehmj s2m43"));
        Assert.Equal(20_000, RemovalCode.DayOf(Day(20_000)));
    }

    [Fact]
    public void Is_valid_for_yesterday_today_and_tomorrow_only_and_only_for_this_pc()
    {
        Assert.True(RemovalCode.Verify(Key, 42, "EEHMJ-S2M43", Day(20_000)));
        Assert.True(RemovalCode.Verify(Key, 42, "EEHMJ-S2M43", Day(20_001)));
        Assert.True(RemovalCode.Verify(Key, 42, "EEHMJ-S2M43", Day(19_999)));
        Assert.False(RemovalCode.Verify(Key, 42, "EEHMJ-S2M43", Day(20_002)));
        Assert.False(RemovalCode.Verify(Key, 43, "EEHMJ-S2M43", Day(20_000)));
        Assert.False(RemovalCode.Verify(Key, 42, "EEHMJ-S2M44", Day(20_000)));
        Assert.False(RemovalCode.Verify(null, 42, "EEHMJ-S2M43", Day(20_000)));
        Assert.False(RemovalCode.Verify(Key, 42, "", Day(20_000)));
    }

    [Theory]
    [InlineData("eehmj-s2m43", "EEHMJ-S2M43")]
    [InlineData(" EEHMJ S2M43 ", "EEHMJ-S2M43")]
    [InlineData("OIL00-00000", "011OO-00000")]
    [InlineData("SHORT", "")]
    [InlineData("EEHMJ-S2M43-X", "")]
    [InlineData(null, "")]
    public void Normalizes_what_people_type(string? typed, string expected)
    {
        // Look-alike letters become digits, so "O" typed for "0" still works.
        var e = expected.Replace('O', '0');
        Assert.Equal(e, RemovalCode.Normalize(typed));
    }

    [Fact]
    public void Rejects_malformed_keys()
    {
        Assert.False(RemovalCode.IsValidKey("short"));
        Assert.False(RemovalCode.IsValidKey(Convert.ToBase64String(new byte[31]) + "AA"));
        Assert.True(RemovalCode.IsValidKey(Key));
        Assert.Throws<ArgumentException>(() => RemovalCode.Compute("bad", 1, 1));
    }

    [Fact]
    public void A_code_is_required_only_when_it_can_be_issued()
    {
        Assert.True(RemovalPolicy.IsCodeRequired(enrolled: true, hasRemovalKey: true, serverStatus: "active"));
        Assert.True(RemovalPolicy.IsCodeRequired(true, true, "disabled"));         // closed from the dashboard: still needs a code
        Assert.False(RemovalPolicy.IsCodeRequired(true, true, "unauthorized"));    // deleted in the dashboard
        Assert.False(RemovalPolicy.IsCodeRequired(true, false, "active"));         // no key yet (older server)
        Assert.False(RemovalPolicy.IsCodeRequired(false, true, null));             // never activated
    }

    [Fact]
    public void Authorization_is_short_lived()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.True(RemovalPolicy.IsAuthorized(now + TimeSpan.FromMinutes(10), now));
        Assert.False(RemovalPolicy.IsAuthorized(now - TimeSpan.FromSeconds(1), now));
        Assert.False(RemovalPolicy.IsAuthorized(now + TimeSpan.FromDays(3), now));   // never trust a far-future value
        Assert.False(RemovalPolicy.IsAuthorized(null, now));
    }
}
