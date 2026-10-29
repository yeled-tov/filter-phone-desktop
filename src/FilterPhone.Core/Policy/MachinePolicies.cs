using System.Xml.Linq;

namespace FilterPhone.Core.Policy;

public enum RegistryValueKind
{
    DWord,
    Text,
}

/// <summary>A machine policy value under HKLM written (and on removal deleted) by the service.</summary>
public sealed record PolicyValue(string KeyPath, string Name, RegistryValueKind Kind, object Value);

/// <summary>
/// Supported machine policies that close bypasses the network filter cannot see. Chrome policies only
/// configure Chrome; they are not what blocks other browsers (that is AppLocker, see AppLockerPolicyBuilder).
/// </summary>
public static class MachinePolicies
{
    public const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";
    public const string AppxKey = @"SOFTWARE\Policies\Microsoft\Windows\Appx";
    public const string SystemKey = @"SOFTWARE\Policies\Microsoft\Windows\System";
    public const string StoreKey = @"SOFTWARE\Policies\Microsoft\WindowsStore";

    public static IReadOnlyList<PolicyValue> Chrome { get; } =
    [
        // The server rejects QUIC (UDP 443) from the tunnel so traffic reaches the filtering proxy over TCP;
        // turning QUIC off avoids the fallback delay.
        new(ChromeKey, "QuicAllowed", RegistryValueKind.DWord, 0),
        // Chrome's own DNS-over-HTTPS would bypass the per-device DNS filtering (AdGuard on the VPN server).
        new(ChromeKey, "DnsOverHttpsMode", RegistryValueKind.Text, "off"),
        // A proxy configured in Chrome (or by an extension) could carry traffic to a non-filtered port.
        new(ChromeKey, "ProxyMode", RegistryValueKind.Text, "direct"),
    ];

    public static IReadOnlyList<PolicyValue> Windows(string defaultAssociationsPath) =>
    [
        // "Prevent non-admin users from installing packaged Windows apps" (Windows 10 1809+): stops a standard
        // user from installing another browser from the Microsoft Store.
        new(AppxKey, "BlockNonAdminUserInstall", RegistryValueKind.DWord, 1),
        // Opens web links in Chrome instead of the blocked default browser (applied at the next sign-in).
        new(SystemKey, "DefaultAssociationsConfiguration", RegistryValueKind.Text, defaultAssociationsPath),
    ];

    /// <summary>
    /// "Turn off the Store application". Windows honours it on Enterprise and Education only; on other editions
    /// the Store is blocked by the packaged-app AppLocker rule and closed by the watchdog.
    /// </summary>
    public static IReadOnlyList<PolicyValue> Store { get; } =
    [
        new(StoreKey, "RemoveWindowsStore", RegistryValueKind.DWord, 1),
    ];

    /// <summary>DISM default-associations file mapping web links and pages to Google Chrome.</summary>
    public static XDocument DefaultAssociations() => new(new XDeclaration("1.0", "UTF-8", null),
        new XElement("DefaultAssociations",
            Assoc(".htm"), Assoc(".html"), Assoc("http"), Assoc("https")));

    private static XElement Assoc(string id) => new("Association",
        new XAttribute("Identifier", id), new XAttribute("ProgId", "ChromeHTML"), new XAttribute("ApplicationName", "Google Chrome"));
}
