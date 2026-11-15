using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace FilterPhone.Core.Trust;

/// <summary>The "ca" object of the enrolment / VPN responses (server: Services.ca_info).</summary>
public sealed record CaInfo(string Pem, string Sha256, string Name)
{
    internal static CaInfo? FromJson(JsonElement parent)
    {
        if (!parent.TryGetProperty("ca", out var ca) || ca.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        var pem = ca.TryGetProperty("pem", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
        if (string.IsNullOrEmpty(pem) || pem.Length > 20_000)
        {
            return null;
        }
        var sha = ca.TryGetProperty("sha256", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() ?? "" : "";
        var name = ca.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : "";
        return new CaInfo(pem, sha.ToLowerInvariant(), name);
    }
}

public sealed class CaValidationException(string message) : Exception(message);

/// <summary>A filtering CA that passed every check and may be offered to the user for trust.</summary>
public sealed record ValidatedCa(byte[] Der, string Sha256, string Subject, DateTimeOffset NotAfter)
{
    public X509Certificate2 Load() => X509CertificateLoader.LoadCertificate(Der);
}

/// <summary>
/// Validates the filtering CA before it can be added to the Windows trust store.
/// The certificate is only accepted from the authenticated API response (TLS to api.filterphone.com),
/// must hash to the fingerprint the server states, must match the optional build-time pin, and must be a
/// self-signed CA with a strong key that is currently valid.
/// </summary>
public static class CaCertificateValidator
{
    public static ValidatedCa Validate(CaInfo info, string expectedPin, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(info);
        var der = ReadSinglePemCertificate(info.Pem);
        var sha = Convert.ToHexStringLower(SHA256.HashData(der));
        if (info.Sha256.Length > 0 && !CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(sha), System.Text.Encoding.ASCII.GetBytes(info.Sha256)))
        {
            throw new CaValidationException("The certificate does not match the fingerprint stated by the server.");
        }
        if (info.Sha256.Length == 0)
        {
            throw new CaValidationException("The server did not state the certificate fingerprint.");
        }
        if (expectedPin.Length > 0 && sha != expectedPin)
        {
            throw new CaValidationException("The certificate does not match the fingerprint pinned in this build.");
        }

        using var cert = X509CertificateLoader.LoadCertificate(der);
        if (cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData) is false)
        {
            throw new CaValidationException("The filtering CA must be a self-signed root certificate.");
        }
        var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (bc is null || !bc.CertificateAuthority)
        {
            throw new CaValidationException("The certificate is not a certificate authority.");
        }
        if (cert.NotBefore.ToUniversalTime() > now.UtcDateTime.AddDays(1) || cert.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            throw new CaValidationException("The certificate is not currently valid.");
        }
        CheckKey(cert);
        var sigOid = cert.SignatureAlgorithm.Value;
        if (sigOid is "1.2.840.113549.1.1.5" or "1.2.840.113549.1.1.4" or "1.2.840.10045.4.1")
        {
            throw new CaValidationException("The certificate uses a weak signature algorithm.");
        }
        return new ValidatedCa(der, sha, cert.Subject, new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero));
    }

    internal static byte[] ReadSinglePemCertificate(string pem)
    {
        var text = pem.AsSpan();
        if (!PemEncoding.TryFind(text, out var fields))
        {
            throw new CaValidationException("The certificate is not in PEM format.");
        }
        if (!text[fields.Label].SequenceEqual("CERTIFICATE"))
        {
            throw new CaValidationException("The PEM block is not a certificate.");
        }
        if (PemEncoding.TryFind(text[fields.Location.End..], out _))
        {
            throw new CaValidationException("Exactly one certificate is expected.");
        }
        var der = new byte[fields.DecodedDataLength];
        if (!Convert.TryFromBase64Chars(text[fields.Base64Data], der, out var written) || written != der.Length)
        {
            throw new CaValidationException("The certificate data is corrupt.");
        }
        return der;
    }

    private static void CheckKey(X509Certificate2 cert)
    {
        using (var rsa = cert.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                if (rsa.KeySize < 2048)
                {
                    throw new CaValidationException("The certificate key is too weak.");
                }
                return;
            }
        }
        using (var ec = cert.GetECDsaPublicKey())
        {
            if (ec is not null)
            {
                if (ec.KeySize < 256)
                {
                    throw new CaValidationException("The certificate key is too weak.");
                }
                return;
            }
        }
        throw new CaValidationException("The certificate key type is not supported.");
    }
}
