using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FilterPhone.Core.Trust;

namespace FilterPhone.Core.Tests;

public class CaValidatorTests
{
    internal static (string Pem, string Sha) MakeCa(bool isCa = true, int rsaBits = 2048, int validDays = 3650,
        int notBeforeDays = -1, string subject = "CN=mitmproxy, O=mitmproxy")
    {
        using var rsa = RSA.Create(rsaBits);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(notBeforeDays), DateTimeOffset.UtcNow.AddDays(validDays));
        var der = cert.Export(X509ContentType.Cert);
        return (cert.ExportCertificatePem(), Convert.ToHexStringLower(SHA256.HashData(der)));
    }

    [Fact]
    public void Accepts_a_valid_self_signed_ca_with_matching_fingerprint()
    {
        var (pem, sha) = MakeCa();
        var v = CaCertificateValidator.Validate(new CaInfo(pem, sha, "FilterPhone CA"), "", DateTimeOffset.UtcNow);
        Assert.Equal(sha, v.Sha256);
        using var loaded = v.Load();
        Assert.Contains("mitmproxy", loaded.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_fingerprint_mismatch()
    {
        var (pem, _) = MakeCa();
        var (_, other) = MakeCa();
        Assert.Throws<CaValidationException>(() =>
            CaCertificateValidator.Validate(new CaInfo(pem, other, ""), "", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rejects_missing_fingerprint()
    {
        var (pem, _) = MakeCa();
        Assert.Throws<CaValidationException>(() => CaCertificateValidator.Validate(new CaInfo(pem, "", ""), "", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Enforces_the_build_pin()
    {
        var (pem, sha) = MakeCa();
        Assert.Throws<CaValidationException>(() =>
            CaCertificateValidator.Validate(new CaInfo(pem, sha, ""), new string('0', 64), DateTimeOffset.UtcNow));
        CaCertificateValidator.Validate(new CaInfo(pem, sha, ""), sha, DateTimeOffset.UtcNow);
    }

    [Fact]
    public void Rejects_non_ca_certificates()
    {
        var (pem, sha) = MakeCa(isCa: false);
        Assert.Throws<CaValidationException>(() => CaCertificateValidator.Validate(new CaInfo(pem, sha, ""), "", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rejects_expired_and_weak_certificates()
    {
        var (pem, sha) = MakeCa(validDays: 1, notBeforeDays: -10);
        Assert.Throws<CaValidationException>(() =>
            CaCertificateValidator.Validate(new CaInfo(pem, sha, ""), "", DateTimeOffset.UtcNow.AddDays(5)));
        var (weakPem, weakSha) = MakeCa(rsaBits: 1024);
        Assert.Throws<CaValidationException>(() =>
            CaCertificateValidator.Validate(new CaInfo(weakPem, weakSha, ""), "", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rejects_bundles_and_garbage()
    {
        var (a, sha) = MakeCa();
        var (b, _) = MakeCa();
        Assert.Throws<CaValidationException>(() => CaCertificateValidator.Validate(new CaInfo(a + b, sha, ""), "", DateTimeOffset.UtcNow));
        Assert.Throws<CaValidationException>(() => CaCertificateValidator.Validate(new CaInfo("hello", sha, ""), "", DateTimeOffset.UtcNow));
        Assert.Throws<CaValidationException>(() => CaCertificateValidator.Validate(
            new CaInfo("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", sha, ""), "", DateTimeOffset.UtcNow));
    }
}
