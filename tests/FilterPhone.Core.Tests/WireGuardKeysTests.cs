using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

public class WireGuardKeysTests
{
    [Fact]
    public void Public_key_matches_rfc7748_test_vector()
    {
        // RFC 7748 section 6.1 (Alice).
        var priv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var expected = Convert.ToBase64String(Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        Assert.Equal(expected, WireGuardKeys.PublicFromPrivate(priv));
    }

    [Fact]
    public void Generated_keys_are_valid_clamped_and_unique()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 50; i++)
        {
            using var kp = WireGuardKeys.Generate();
            Assert.True(WireGuardKeys.IsValidKey(kp.PublicKey));
            var priv = Convert.FromBase64String(kp.PrivateKeyBase64());
            Assert.Equal(0, priv[0] & 7);
            Assert.Equal(64, priv[31] & 0xC0);
            Assert.True(seen.Add(kp.PublicKey));
        }
    }

    [Fact]
    public void Private_key_round_trips_and_is_not_in_ToString()
    {
        using var kp = WireGuardKeys.Generate();
        using var again = WireGuardKeys.FromPrivateKey(kp.PrivateKeyBase64());
        Assert.Equal(kp.PublicKey, again.PublicKey);
        Assert.DoesNotContain(kp.PrivateKeyBase64(), kp.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
    [InlineData("lfTRXEWxt8mZc8cjSvOWN3tqnTpWw4v2Eg3qF6WTklx=")]
    [InlineData("lfTRXEWxt8mZc8cjSvOWN3tqnTpWw4v2Eg3qF6WTklw")]
    public void Invalid_keys_are_rejected_like_the_server(string key) => Assert.False(WireGuardKeys.IsValidKey(key));
}
