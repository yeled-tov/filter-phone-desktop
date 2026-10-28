using Microsoft.Win32;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// The informed consent the administrator gave in the installer (written to HKLM by the elevated installer).
/// The service never trusts the filtering CA, installs the network lock or restricts browsers without it.
/// </summary>
internal static class Consent
{
    public static bool CertificateTrust => Read("CertificateTrust");
    public static bool NetworkLock => Read("NetworkLock");
    public static bool ChromeOnly => Read("ChromeOnly");

    private static bool Read(string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(Paths.ConsentKey);
        return key?.GetValue(name) is int v && v == 1;
    }
}
