using System.Security.Cryptography.X509Certificates;
using FilterPhone.Core.Trust;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Trust;

/// <summary>
/// Adds the validated FilterPhone filtering CA to LocalMachine\Root (so Chrome, which honours locally
/// trusted roots, accepts certificates from the filtering proxy) and removes only certificates this product
/// added, tracked by thumbprint. Requires the administrator's consent recorded by the installer.
/// </summary>
internal sealed class TrustStore(ILogger<TrustStore> log)
{
    public const string FriendlyName = "FilterPhone filtering CA (added by FilterPhone Desktop)";

    public static bool IsTrusted(string thumbprint)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false).Count > 0;
    }

    /// <summary>Returns the Windows (SHA-1) thumbprint of the installed certificate.</summary>
    public string Add(ValidatedCa ca)
    {
        ArgumentNullException.ThrowIfNull(ca);
        using var cert = ca.Load();
        cert.FriendlyName = FriendlyName;
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        if (store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count == 0)
        {
            store.Add(cert);
            log.LogInformation("Filtering CA added to the machine trust store (sha256 {Sha})", ca.Sha256[..16]);
        }
        return cert.Thumbprint;
    }

    public void Remove(IEnumerable<string> thumbprints)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        foreach (var tp in thumbprints)
        {
            foreach (var c in store.Certificates.Find(X509FindType.FindByThumbprint, tp, false))
            {
                // Only certificates we added: same thumbprint we recorded and our friendly name.
                if (c.FriendlyName == FriendlyName)
                {
                    store.Remove(c);
                    log.LogInformation("Filtering CA removed from the machine trust store ({Tp})", tp[..8]);
                }
                c.Dispose();
            }
        }
    }
}
