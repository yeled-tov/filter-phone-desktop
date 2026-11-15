using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using FilterPhone.Core.Trust;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Ipc;
using FilterPhone.Service.Policy;
using FilterPhone.Service.Trust;
using Microsoft.Extensions.Logging.Abstractions;

namespace FilterPhone.Windows.Tests;

public class DpapiTests
{
    [Fact]
    public void Round_trips_and_binds_entropy()
    {
        var secret = Encoding.UTF8.GetBytes("PrivateKey = test-only");
        var blob = Dpapi.Protect(secret, "FilterPhone", "entropy"u8);
        Assert.DoesNotContain("test-only", Encoding.UTF8.GetString(blob), StringComparison.Ordinal);
        Assert.Equal(secret, Dpapi.Unprotect(blob, "entropy"u8));
        Assert.Throws<System.ComponentModel.Win32Exception>(() => Dpapi.Unprotect(blob, "other"u8));
    }

    [Fact]
    public void WireGuard_dpapi_format_carries_the_tunnel_name_as_description()
    {
        // wireguard-windows refuses a .conf.dpapi whose DPAPI description differs from the tunnel name.
        var blob = Dpapi.Protect("[Interface]\n"u8, "FilterPhone");
        Assert.Equal("FilterPhone", DpapiDescription(blob));
    }

    private static unsafe string? DpapiDescription(byte[] blob)
    {
        fixed (byte* p = blob)
        {
            var input = new FilterPhone.Service.Native.DATA_BLOB { cbData = (uint)blob.Length, pbData = (IntPtr)p };
            var output = default(FilterPhone.Service.Native.DATA_BLOB);
            IntPtr desc;
            Assert.True(FilterPhone.Service.Native.Win32.CryptUnprotectData(&input, &desc, null, IntPtr.Zero, IntPtr.Zero, 1, &output));
            var s = System.Runtime.InteropServices.Marshal.PtrToStringUni(desc);
            FilterPhone.Service.Native.Win32.LocalFree(desc);
            FilterPhone.Service.Native.Win32.LocalFree(output.pbData);
            return s;
        }
    }
}

public class PipeSecurityTests
{
    [Fact]
    public void Pipe_admits_interactive_users_and_denies_network_logons()
    {
        var rules = PipeServer.CreateSecurity().GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var anonymous = new SecurityIdentifier(WellKnownSidType.AnonymousSid, null);
        Assert.Contains(rules, r => r.IdentityReference.Equals(interactive) && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r => r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny);
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(everyone) || r.IdentityReference.Equals(anonymous));
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(interactive) && r.PipeAccessRights.HasFlag(PipeAccessRights.ChangePermissions));
    }
}

[Collection("store")]
public class TrustStoreTests
{
    [Fact]
    public void Adds_and_removes_only_its_own_certificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=FilterPhone Desktop CI test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var der = cert.Export(X509ContentType.Cert);
        var sha = Convert.ToHexStringLower(SHA256.HashData(der));
        var validated = CaCertificateValidator.Validate(new CaInfo(cert.ExportCertificatePem(), sha, ""), "", DateTimeOffset.UtcNow);

        var store = new TrustStore(NullLogger<TrustStore>.Instance);
        var tp = store.Add(validated);
        try
        {
            Assert.True(TrustStore.IsTrusted(tp));
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            Assert.True(chain.Build(cert), "the machine now trusts the CA");
        }
        finally
        {
            store.Remove([tp]);
        }
        Assert.False(TrustStore.IsTrusted(tp));
    }
}

public class SignatureTests
{
    [Fact]
    public void Embedded_signature_is_verified_and_the_publisher_is_checked()
    {
        // The test host is Authenticode-signed by Microsoft (embedded signature).
        var host = Environment.ProcessPath!;
        Assert.True(SignatureVerifier.IsTrusted(host, "Microsoft Corporation", out var ok), ok);
        Assert.False(SignatureVerifier.IsTrusted(host, SignatureVerifier.WireGuardPublisher, out var why));
        Assert.Equal("unexpected_publisher", why);
    }

    [Fact]
    public void Unsigned_or_missing_files_are_not_trusted()
    {
        var tmp = Path.GetTempFileName();
        File.WriteAllText(tmp, "not a binary");
        Assert.False(SignatureVerifier.IsTrusted(tmp, SignatureVerifier.WireGuardPublisher, out _));
        File.Delete(tmp);
        Assert.False(SignatureVerifier.IsTrusted(tmp, SignatureVerifier.WireGuardPublisher, out var why));
        Assert.Equal("missing", why);
    }
}

public class WindowsInfoTests
{
    [Theory]
    [InlineData("Enterprise", "LocalPolicy")]
    [InlineData("Education", "LocalPolicy")]
    [InlineData("ServerDatacenter", "LocalPolicy")]
    [InlineData("Professional", "ProWithVerification")]
    [InlineData("Core", "Unsupported")]
    [InlineData("CoreSingleLanguage", "Unsupported")]
    public void Editions_are_classified(string edition, string expected) =>
        Assert.Equal(expected, WindowsInfo.Classify(edition).ToString());

    [Fact]
    public void Reads_the_running_windows() => Assert.False(string.IsNullOrEmpty(WindowsInfo.Build));

    [Fact]
    public void Launch_probe_reports_missing_programs() =>
        Assert.Equal(LaunchResult.NotFound, LaunchProbe.Try(@"C:\does-not-exist\browser.exe"));
}
