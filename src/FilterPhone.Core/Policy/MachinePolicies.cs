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

    public const string CopilotKey = @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot";
    public const string DshKey = @"SOFTWARE\Policies\Microsoft\Dsh";
    public const string CloudContentKey = @"SOFTWARE\Policies\Microsoft\Windows\CloudContent";
    public const string ExplorerKey = @"SOFTWARE\Policies\Microsoft\Windows\Explorer";
    public const string SearchKey = @"SOFTWARE\Policies\Microsoft\Windows\Windows Search";
    // The "All Removable Storage classes: Deny all access" policy (a well-known device-class GUID).
    public const string RemovableKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

    /// <summary>
    /// Optional Windows-only blocks the administrator turns on per computer in the dashboard (keys match
    /// catalog.DESKTOP_DEFAULTS). Each is a standard Group Policy registry value and fully reversible; the
    /// service applies a group only while its toggle is on and restores the original on uninstall.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<PolicyValue>> DesktopExtras { get; } =
        new Dictionary<string, IReadOnlyList<PolicyValue>>(StringComparer.Ordinal)
        {
            ["block_copilot"] = [new(CopilotKey, "TurnOffWindowsCopilot", RegistryValueKind.DWord, 1)],
            ["block_widgets"] = [new(DshKey, "AllowNewsAndInterests", RegistryValueKind.DWord, 0)],
            ["block_spotlight"] =
            [
                new(CloudContentKey, "DisableWindowsSpotlightFeatures", RegistryValueKind.DWord, 1),
                new(CloudContentKey, "DisableSpotlightCollectionOnDesktop", RegistryValueKind.DWord, 1),
            ],
            ["block_web_search"] =
            [
                new(ExplorerKey, "DisableSearchBoxSuggestions", RegistryValueKind.DWord, 1),
                new(SearchKey, "ConnectedSearchUseWeb", RegistryValueKind.DWord, 0),
            ],
            ["block_removable"] = [new(RemovableKey, "Deny_All", RegistryValueKind.DWord, 1)],
        };

    /// <summary>DISM default-associations file mapping web links and pages to Google Chrome.</summary>
    public static XDocument DefaultAssociations() => new(new XDeclaration("1.0", "UTF-8", null),
        new XElement("DefaultAssociations",
            Assoc(".htm"), Assoc(".html"), Assoc("http"), Assoc("https")));

    private static XElement Assoc(string id) => new("Association",
        new XAttribute("Identifier", id), new XAttribute("ProgId", "ChromeHTML"), new XAttribute("ApplicationName", "Google Chrome"));
}
