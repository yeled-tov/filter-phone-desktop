using System.Xml.Linq;

namespace FilterPhone.Core.Policy;

/// <summary>
/// Builds the AppLocker policy that makes Google Chrome the only browser for the computer's users.
///
/// Model (AppLocker is an allow-list once executable rules exist):
///  * Everyone may run programs from %WINDIR% and %PROGRAMFILES%, except folders that ordinary users can
///    write to inside %WINDIR% (so a portable browser cannot be copied there) and the installation
///    folders of other browsers inside %PROGRAMFILES%.
///  * Everyone may run Google Chrome and its updater wherever they are installed (publisher rule), and
///    per-user Microsoft OneDrive.
///  * Administrators may run any program except the denied browsers.
///  * Microsoft Edge and Internet Explorer are denied by publisher + product for everyone (deny wins).
///  * Anything else - including portable browsers in Downloads, AppData, USB drives or %TEMP% - is not
///    allowed for standard users.
/// Packaged (Store) apps are not restricted by this policy; non-admin installation of packaged apps is
/// blocked by a separate supported policy (see ChromePolicies.MachinePolicies).
/// </summary>
public static class AppLockerPolicyBuilder
{
    public const string Everyone = "S-1-1-0";
    public const string Administrators = "S-1-5-32-544";

    /// <summary>Present in every policy we write; used to recognise (and only ever remove) our own policy.</summary>
    public const string MarkerRuleId = "6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c01";
    public const string RuleNamePrefix = "FilterPhone: ";

    private const string MicrosoftPublisher = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
    private const string GooglePublisher = "O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US";

    /// <summary>Sub-folders of %WINDIR% that standard users can write to (well-known AppLocker gaps).</summary>
    public static readonly string[] UserWritableWindowsFolders =
    [
        @"%WINDIR%\Tasks\*",
        @"%WINDIR%\Temp\*",
        @"%WINDIR%\tracing\*",
        @"%WINDIR%\Registration\CRMLog\*",
        @"%WINDIR%\debug\wia\*",
        @"%WINDIR%\PLA\Reports\*",
        @"%WINDIR%\PLA\Rules\*",
        @"%WINDIR%\PLA\Templates\*",
        @"%WINDIR%\System32\Tasks\*",
        @"%WINDIR%\System32\Tasks_Migrated\*",
        @"%WINDIR%\System32\spool\drivers\color\*",
        @"%WINDIR%\System32\spool\PRINTERS\*",
        @"%WINDIR%\System32\spool\SERVERS\*",
        @"%WINDIR%\System32\Microsoft\Crypto\RSA\MachineKeys\*",
        @"%WINDIR%\System32\com\dmp\*",
        @"%WINDIR%\System32\FxsTmp\*",
        @"%WINDIR%\SysWOW64\Tasks\*",
        @"%WINDIR%\SysWOW64\com\dmp\*",
        @"%WINDIR%\SysWOW64\FxsTmp\*",
    ];

    /// <summary>Browser installation folders under Program Files (both 64- and 32-bit).</summary>
    public static readonly string[] BlockedBrowserFolders =
    [
        @"%PROGRAMFILES%\Microsoft\Edge\*",
        @"%PROGRAMFILES%\Microsoft\Edge Beta\*",
        @"%PROGRAMFILES%\Microsoft\Edge Dev\*",
        @"%PROGRAMFILES%\Internet Explorer\*",
        @"%PROGRAMFILES%\Mozilla Firefox\*",
        @"%PROGRAMFILES%\Firefox Developer Edition\*",
        @"%PROGRAMFILES%\Firefox Nightly\*",
        @"%PROGRAMFILES%\BraveSoftware\*",
        @"%PROGRAMFILES%\Opera\*",
        @"%PROGRAMFILES%\Opera GX\*",
        @"%PROGRAMFILES%\Vivaldi\*",
        @"%PROGRAMFILES%\Yandex\*",
        @"%PROGRAMFILES%\Waterfox\*",
        @"%PROGRAMFILES%\Pale Moon\*",
        @"%PROGRAMFILES%\LibreWolf\*",
        @"%PROGRAMFILES%\Chromium\*",
        @"%PROGRAMFILES%\Tor Browser\*",
        @"%PROGRAMFILES%\Maxthon\*",
        @"%PROGRAMFILES%\SeaMonkey\*",
        @"%PROGRAMFILES%\DuckDuckGo\*",
    ];

    public static XDocument Build()
    {
        var exe = new XElement("RuleCollection", new XAttribute("Type", "Exe"), new XAttribute("EnforcementMode", "Enabled"));
        exe.Add(PathRule(MarkerRuleId, "Windows folder", Everyone, "Allow", @"%WINDIR%\*", UserWritableWindowsFolders));
        exe.Add(PathRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c02", "Program Files (other browsers excluded)", Everyone, "Allow",
            @"%PROGRAMFILES%\*", BlockedBrowserFolders));
        exe.Add(PathRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c03", "Administrators (other browsers excluded)", Administrators, "Allow",
            "*", BlockedBrowserFolders));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c04", "Google Chrome", Everyone, "Allow", GooglePublisher, "GOOGLE CHROME", "*"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c05", "Google Updater", Everyone, "Allow", GooglePublisher, "GOOGLE UPDATER", "*"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c06", "Google Update", Everyone, "Allow", GooglePublisher, "GOOGLE UPDATE", "*"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c07", "Microsoft OneDrive", Everyone, "Allow", MicrosoftPublisher, "MICROSOFT ONEDRIVE", "*"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c08", "Block Microsoft Edge", Everyone, "Deny", MicrosoftPublisher, "MICROSOFT EDGE", "MSEDGE.EXE"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c09", "Block Microsoft Edge (PWA launcher)", Everyone, "Deny", MicrosoftPublisher, "MICROSOFT EDGE", "MSEDGE_PROXY.EXE"));
        exe.Add(PublisherRule("6f1d3c9e-6a3b-4f53-9d55-0f7e1a2b3c0a", "Block Internet Explorer", Everyone, "Deny", MicrosoftPublisher, "INTERNET EXPLORER", "IEXPLORE.EXE"));

        var root = new XElement("AppLockerPolicy", new XAttribute("Version", "1"),
            exe,
            NotConfigured("Msi"),
            NotConfigured("Script"),
            NotConfigured("Dll"),
            NotConfigured("Appx"));
        return new XDocument(new XDeclaration("1.0", "utf-8", null), root);
    }

    /// <summary>The empty policy written on removal (only if the current policy is ours).</summary>
    public static XDocument Empty() => new(new XDeclaration("1.0", "utf-8", null),
        new XElement("AppLockerPolicy", new XAttribute("Version", "1"),
            NotConfigured("Exe"), NotConfigured("Msi"), NotConfigured("Script"), NotConfigured("Dll"), NotConfigured("Appx")));

    /// <summary>The executable rule collection alone (the AppLocker CSP "EXE" node takes this fragment).</summary>
    public static string ExeCollectionXml() =>
        Build().Root!.Elements("RuleCollection").First(e => (string?)e.Attribute("Type") == "Exe")
            .ToString(SaveOptions.DisableFormatting);

    public static bool IsOurs(string? policyXml) =>
        !string.IsNullOrEmpty(policyXml) && policyXml.Contains(MarkerRuleId, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the policy contains any executable rule (a policy that is not ours and not empty).</summary>
    public static bool HasExecutableRules(string? policyXml)
    {
        if (string.IsNullOrWhiteSpace(policyXml))
        {
            return false;
        }
        var doc = XDocument.Parse(policyXml);
        return doc.Descendants("RuleCollection")
            .Where(rc => string.Equals((string?)rc.Attribute("Type"), "Exe", StringComparison.OrdinalIgnoreCase))
            .Any(rc => rc.Elements().Any());
    }

    private static XElement NotConfigured(string type) =>
        new("RuleCollection", new XAttribute("Type", type), new XAttribute("EnforcementMode", "NotConfigured"));

    private static XElement PathRule(string id, string name, string sid, string action, string path, IEnumerable<string> exceptions)
    {
        var rule = new XElement("FilePathRule",
            new XAttribute("Id", id), new XAttribute("Name", RuleNamePrefix + name),
            new XAttribute("Description", "Managed by FilterPhone Desktop"),
            new XAttribute("UserOrGroupSid", sid), new XAttribute("Action", action),
            new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", path))));
        var ex = exceptions.ToList();
        if (ex.Count > 0)
        {
            rule.Add(new XElement("Exceptions", ex.Select(p => new XElement("FilePathCondition", new XAttribute("Path", p)))));
        }
        return rule;
    }

    private static XElement PublisherRule(string id, string name, string sid, string action, string publisher, string product, string binary) =>
        new("FilePublisherRule",
            new XAttribute("Id", id), new XAttribute("Name", RuleNamePrefix + name),
            new XAttribute("Description", "Managed by FilterPhone Desktop"),
            new XAttribute("UserOrGroupSid", sid), new XAttribute("Action", action),
            new XElement("Conditions",
                new XElement("FilePublisherCondition",
                    new XAttribute("PublisherName", publisher), new XAttribute("ProductName", product),
                    new XAttribute("BinaryName", binary),
                    new XElement("BinaryVersionRange", new XAttribute("LowSection", "*"), new XAttribute("HighSection", "*")))));
}
