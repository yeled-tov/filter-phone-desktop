using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;
using FilterPhone.Core.Network;
using FilterPhone.Core.Policy;

namespace FilterPhone.Core.Tests;

public class AppLockerPolicyTests
{
    private static readonly XDocument Policy = AppLockerPolicyBuilder.Build();

    private static IEnumerable<XElement> ExeRules() =>
        Policy.Root!.Elements("RuleCollection").Single(e => (string?)e.Attribute("Type") == "Exe").Elements();

    private static Dictionary<string, string> Modes(XDocument policy) => policy.Root!.Elements("RuleCollection")
        .ToDictionary(e => (string)e.Attribute("Type")!, e => (string)e.Attribute("EnforcementMode")!);

    [Fact]
    public void Only_executable_and_packaged_app_rules_are_enforced()
    {
        var collections = Modes(Policy);
        Assert.Equal("Enabled", collections["Exe"]);
        Assert.Equal("Enabled", collections["Appx"]);
        Assert.All(new[] { "Msi", "Script", "Dll" }, t => Assert.Equal("NotConfigured", collections[t]));
        Assert.Equal("NotConfigured", Modes(AppLockerPolicyBuilder.Build(blockStore: false))["Appx"]);
    }

    [Fact]
    public void Store_option_denies_only_the_microsoft_store_and_keeps_other_packaged_apps()
    {
        var appx = Policy.Root!.Elements("RuleCollection").Single(e => (string?)e.Attribute("Type") == "Appx").Elements().ToList();
        Assert.Equal(2, appx.Count);
        var allow = appx.Single(r => (string?)r.Attribute("Action") == "Allow");
        var deny = appx.Single(r => (string?)r.Attribute("Action") == "Deny");
        var allowCondition = allow.Descendants("FilePublisherCondition").Single();
        Assert.Equal("*", (string?)allowCondition.Attribute("PublisherName"));
        Assert.Equal("*", (string?)allowCondition.Attribute("ProductName"));
        var denyCondition = deny.Descendants("FilePublisherCondition").Single();
        Assert.Equal("Microsoft.WindowsStore", (string?)denyCondition.Attribute("ProductName"));
        Assert.Equal(AppLockerPolicyBuilder.StorePackagePublisher, (string?)denyCondition.Attribute("PublisherName"));
        Assert.All(appx, r => Assert.Equal(AppLockerPolicyBuilder.Everyone, (string?)r.Attribute("UserOrGroupSid")));
        Assert.StartsWith("<RuleCollection Type=\"Appx\"", AppLockerPolicyBuilder.AppxCollectionXml(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_store_only_policy_is_still_recognised_as_ours()
    {
        var storeOnly = AppLockerPolicyBuilder.Build(chromeOnly: false, blockStore: true).ToString();
        Assert.True(AppLockerPolicyBuilder.IsOurs(storeOnly));
        Assert.False(AppLockerPolicyBuilder.HasExecutableRules(storeOnly));
        Assert.True(AppLockerPolicyBuilder.HasAnyRules(storeOnly));
        Assert.False(AppLockerPolicyBuilder.HasAnyRules(AppLockerPolicyBuilder.Empty().ToString()));
        Assert.Equal("NotConfigured", Modes(AppLockerPolicyBuilder.Build(chromeOnly: false, blockStore: true))["Exe"]);
    }

    [Fact]
    public void Store_machine_policy_turns_off_the_store_application()
    {
        var v = Assert.Single(MachinePolicies.Store);
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\WindowsStore", v.KeyPath);
        Assert.Equal("RemoveWindowsStore", v.Name);
        Assert.Equal(1, v.Value);
    }

    [Fact]
    public void Edge_and_internet_explorer_are_denied_for_everyone()
    {
        var denies = ExeRules().Where(r => (string?)r.Attribute("Action") == "Deny").ToList();
        Assert.Equal(3, denies.Count);
        Assert.All(denies, d => Assert.Equal(AppLockerPolicyBuilder.Everyone, (string?)d.Attribute("UserOrGroupSid")));
        var binaries = denies.Select(d => (string?)d.Descendants("FilePublisherCondition").Single().Attribute("BinaryName")).ToList();
        Assert.Contains("MSEDGE.EXE", binaries);
        Assert.Contains("IEXPLORE.EXE", binaries);
        // WebView2 (a different product) is not denied, so apps that embed it keep working.
        Assert.DoesNotContain(denies, d => ((string?)d.Descendants("FilePublisherCondition").Single().Attribute("ProductName"))!.Contains("WEBVIEW", StringComparison.Ordinal));
    }

    [Fact]
    public void Chrome_is_allowed_wherever_it_is_installed()
    {
        var chrome = ExeRules().Single(r => ((string?)r.Attribute("Name"))!.EndsWith("Google Chrome", StringComparison.Ordinal));
        Assert.Equal("Allow", (string?)chrome.Attribute("Action"));
        Assert.Equal("GOOGLE CHROME", (string?)chrome.Descendants("FilePublisherCondition").Single().Attribute("ProductName"));
    }

    [Fact]
    public void User_writable_windows_folders_and_browser_folders_are_excluded()
    {
        var windows = ExeRules().Single(r => (string?)r.Attribute("Id") == AppLockerPolicyBuilder.MarkerRuleId);
        var exceptions = windows.Element("Exceptions")!.Elements().Select(e => (string)e.Attribute("Path")!).ToList();
        Assert.Contains(@"%WINDIR%\Temp\*", exceptions);
        Assert.Contains(@"%WINDIR%\System32\spool\drivers\color\*", exceptions);

        var programFiles = ExeRules().Single(r => (string?)r.Descendants("FilePathCondition").FirstOrDefault()?.Attribute("Path") == @"%PROGRAMFILES%\*");
        var pfExceptions = programFiles.Element("Exceptions")!.Elements().Select(e => (string)e.Attribute("Path")!).ToList();
        Assert.Contains(@"%PROGRAMFILES%\Mozilla Firefox\*", pfExceptions);
        Assert.Contains(@"%PROGRAMFILES%\BraveSoftware\*", pfExceptions);
        Assert.Contains(@"%PROGRAMFILES%\Microsoft\Edge\*", pfExceptions);
    }

    [Fact]
    public void No_rule_allows_user_profile_paths()
    {
        var paths = ExeRules().Where(r => (string?)r.Attribute("Action") == "Allow"
                                          && (string?)r.Attribute("UserOrGroupSid") == AppLockerPolicyBuilder.Everyone)
            .SelectMany(r => r.Element("Conditions")!.Elements("FilePathCondition")).Select(c => (string)c.Attribute("Path")!);
        Assert.All(paths, p => Assert.True(p.StartsWith("%WINDIR%", StringComparison.Ordinal) || p.StartsWith("%PROGRAMFILES%", StringComparison.Ordinal)));
    }

    [Fact]
    public void Rule_ids_are_unique_and_our_policy_is_recognised()
    {
        var ids = Policy.Descendants("FilePublisherRule").Concat(Policy.Descendants("FilePathRule"))
            .Select(r => (string)r.Attribute("Id")!).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(ids, id => Assert.True(Guid.TryParse(id, out _)));
        var xml = Policy.ToString();
        Assert.True(AppLockerPolicyBuilder.IsOurs(xml));
        Assert.True(AppLockerPolicyBuilder.HasExecutableRules(xml));
        Assert.False(AppLockerPolicyBuilder.IsOurs(AppLockerPolicyBuilder.Empty().ToString()));
        Assert.False(AppLockerPolicyBuilder.HasExecutableRules(AppLockerPolicyBuilder.Empty().ToString()));
        Assert.StartsWith("<RuleCollection Type=\"Exe\"", AppLockerPolicyBuilder.ExeCollectionXml(), StringComparison.Ordinal);
    }

    [Fact]
    public void Default_associations_point_web_links_to_chrome()
    {
        var doc = MachinePolicies.DefaultAssociations();
        var ids = doc.Root!.Elements("Association").Select(a => ((string)a.Attribute("Identifier")!, (string)a.Attribute("ProgId")!)).ToList();
        Assert.Contains(("https", "ChromeHTML"), ids);
        Assert.Contains(("http", "ChromeHTML"), ids);
    }

    [Fact]
    public void Chrome_policies_close_network_bypasses()
    {
        var names = MachinePolicies.Chrome.ToDictionary(p => p.Name, p => p.Value);
        Assert.Equal(0, names["QuicAllowed"]);
        Assert.Equal("off", names["DnsOverHttpsMode"]);
        Assert.Equal("direct", names["ProxyMode"]);
        Assert.All(MachinePolicies.Chrome, p => Assert.StartsWith(@"SOFTWARE\Policies\Google\Chrome", p.KeyPath, StringComparison.Ordinal));
    }
}

public class KillSwitchPlanTests
{
    private static readonly KillSwitchInputs Inputs = new(
        IPAddress.Parse("10.8.0.10"),
        [IPAddress.Parse("151.145.88.42")],
        51820,
        [IPAddress.Parse("151.145.88.42")],
        @"C:\Program Files\FilterPhone Desktop\FilterPhone.Service.exe");

    [Fact]
    public void Blocks_everything_else_on_both_families()
    {
        var rules = KillSwitchPlan.Build(Inputs);
        var blocks = rules.Where(r => r.Action == RuleAction.Block).ToList();
        Assert.Equal(2, blocks.Count);
        Assert.Contains(blocks, b => b.Family == AddressFamily.InterNetwork);
        Assert.Contains(blocks, b => b.Family == AddressFamily.InterNetworkV6);
        Assert.All(blocks, b => Assert.True(b.RemoteNetworks.Count == 0 && b.LocalAddress is null && b.ApplicationPath is null));
        Assert.All(rules.Where(r => r.Action == RuleAction.Permit), p => Assert.True(p.Weight > blocks[0].Weight));
    }

    [Fact]
    public void Permits_are_narrow()
    {
        var rules = KillSwitchPlan.Build(Inputs);
        var tunnel = rules.Single(r => r.LocalAddress is not null);
        Assert.Equal(IPAddress.Parse("10.8.0.10"), tunnel.LocalAddress);

        var endpoint = rules.Single(r => r.RemotePort == 51820);
        Assert.Equal(RuleProtocol.Udp, endpoint.Protocol);
        Assert.Equal([(IPAddress.Parse("151.145.88.42"), 32)], endpoint.RemoteNetworks);

        var api = rules.Single(r => r.ApplicationPath is not null);
        Assert.Equal(RuleProtocol.Tcp, api.Protocol);
        Assert.Equal((ushort)443, api.RemotePort);

        // No permit other than loopback is unconditional (no permit without any condition).
        Assert.All(rules.Where(r => r.Action == RuleAction.Permit), r =>
            Assert.True(r.Loopback || r.LocalAddress is not null || r.RemotePort is not null || r.RemoteNetworks.Count > 0));
        // IPv6 is only permitted on the local link.
        var v6Permits = rules.Where(r => r.Action == RuleAction.Permit && r.Family == AddressFamily.InterNetworkV6 && !r.Loopback && r.RemotePort is null);
        Assert.All(v6Permits, r => Assert.All(r.RemoteNetworks, n => Assert.True(n.Address.IsIPv6LinkLocal || n.Address.IsIPv6Multicast)));
    }

    [Fact]
    public void Validates_inputs()
    {
        Assert.Throws<ArgumentException>(() => KillSwitchPlan.Build(Inputs with { EndpointAddresses = [] }));
        Assert.Throws<ArgumentException>(() => KillSwitchPlan.Build(Inputs with { TunnelAddress = IPAddress.IPv6Loopback }));
        Assert.Throws<ArgumentException>(() => KillSwitchPlan.Build(Inputs with { ServiceExecutablePath = "FilterPhone.Service.exe" }));
    }
}
