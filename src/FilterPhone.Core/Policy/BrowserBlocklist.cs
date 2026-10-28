namespace FilterPhone.Core.Policy;

/// <summary>
/// Decides whether a running program is a browser that must not run on a protected PC. Used both by the
/// AppLocker policy (prevention) and by the service's watchdog (termination). The decision is based first
/// on the program's signed version metadata (product name) and only then on its executable file name, so a
/// renamed browser is still caught by its product name. Google Chrome — the one permitted browser — is
/// never matched. Pure and cross-platform so it is unit-tested on every OS.
/// </summary>
public static class BrowserBlocklist
{
    /// <summary>Product names (as they appear in the signed version info) of browsers that are blocked.</summary>
    private static readonly string[] BlockedProducts =
    [
        "MICROSOFT EDGE", "INTERNET EXPLORER", "FIREFOX", "MOZILLA FIREFOX", "WATERFOX", "PALE MOON", "PALEMOON",
        "LIBREWOLF", "SEAMONKEY", "TOR BROWSER", "BRAVE", "OPERA", "OPERA GX", "VIVALDI", "YANDEX", "CHROMIUM",
        "MAXTHON", "UC BROWSER", "UCBROWSER", "EPIC PRIVACY BROWSER", "SLIMJET", "CENT BROWSER", "COC COC",
        "COCCOC", "COMODO DRAGON", "IRON", "SRWARE IRON", "TORCH", "AVAST SECURE BROWSER", "AVG SECURE BROWSER",
        "DUCKDUCKGO", "MULLVAD BROWSER", "FLOORP", "THORIUM", "SUPERMIUM", "FALKON", "MIDORI", "QUTEBROWSER",
        "MIN", "PUFFIN", "DOLPHIN", "GHOST BROWSER", "BLISK", "KIWI BROWSER", "SAMSUNG INTERNET",
    ];

    /// <summary>Executable file names of blocked browsers (fallback when version info is missing).</summary>
    private static readonly HashSet<string> BlockedFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "msedge_proxy.exe", "ie_to_edge_stub.exe", "iexplore.exe",
        "firefox.exe", "waterfox.exe", "palemoon.exe", "librewolf.exe", "seamonkey.exe", "floorp.exe",
        "brave.exe", "opera.exe", "opera_gx.exe", "launcher.exe", "vivaldi.exe", "yandex.exe", "browser.exe",
        "chromium.exe", "thorium.exe", "supermium.exe", "maxthon.exe", "ucbrowser.exe", "epic.exe",
        "slimjet.exe", "centbrowser.exe", "coccoc.exe", "dragon.exe", "iron.exe", "torch.exe", "falkon.exe",
        "midori.exe", "qutebrowser.exe", "min.exe", "tor.exe", "mullvadbrowser.exe", "kiwi.exe",
    };

    /// <summary>Product names that are always allowed, even if a file name heuristic would match.</summary>
    private static readonly string[] AllowedProducts = ["GOOGLE CHROME", "GOOGLE CHROME FOR TESTING"];

    /// <summary>
    /// True when the program should be blocked/terminated. <paramref name="fileName"/> is the executable's
    /// own file name (not a full path); the others come from its version info and may be null/empty.
    /// </summary>
    public static bool IsBlockedBrowser(string? productName, string? companyName, string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        var product = (productName ?? string.Empty).Trim().ToUpperInvariant();
        if (product.Length > 0 && AllowedProducts.Any(a => product == a))
        {
            return false;
        }
        if (product.Length > 0 && BlockedProducts.Any(b => product == b || product.Contains(b, StringComparison.Ordinal)))
        {
            return true;
        }
        // "browser.exe" and "launcher.exe" are generic; only block them when the product/company confirms a
        // blocked vendor (otherwise a legitimate app's launcher.exe could be caught).
        var name = fileName.Trim();
        if (name is var _ && (name.Equals("browser.exe", StringComparison.OrdinalIgnoreCase)
                              || name.Equals("launcher.exe", StringComparison.OrdinalIgnoreCase)))
        {
            var company = (companyName ?? string.Empty).ToUpperInvariant();
            return company.Contains("YANDEX", StringComparison.Ordinal) || company.Contains("OPERA", StringComparison.Ordinal)
                || product.Contains("YANDEX", StringComparison.Ordinal) || product.Contains("OPERA", StringComparison.Ordinal);
        }
        return BlockedFileNames.Contains(name);
    }
}
