using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Policy;

namespace FilterPhone.Windows.Tests;

/// <summary>
/// Evaluates the generated AppLocker policy with Windows' own engine (Test-AppLockerPolicy) for a real standard
/// user, without applying it to the build machine. Proves the XML is valid and the rules decide as designed.
/// The CI workflow creates the standard account and passes its name in FP_TEST_STANDARD_USER.
/// </summary>
public sealed class AppLockerEvaluationTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("fp-applocker-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Pf(string rel) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), rel);
    private static string Pf86(string rel) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), rel);

    private async Task<Dictionary<string, string>> EvaluateAsync(string user, IEnumerable<string> paths)
    {
        var xml = Path.Combine(_dir, "policy.xml");
        File.WriteAllText(xml, AppLockerPolicyBuilder.Build().ToString());
        var list = string.Join(",", paths.Select(p => "'" + p.Replace("'", "''", StringComparison.Ordinal) + "'"));
        var r = await ProcessRunner.RunAsync(ProcessRunner.PowerShell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             $"Import-Module AppLocker; Test-AppLockerPolicy -XmlPolicy '{xml}' -Path @({list}) -User '{user}' | " +
             "ForEach-Object { \"$($_.FilePath)|$($_.PolicyDecision)\" }"],
            TimeSpan.FromMinutes(2), CancellationToken.None);
        Assert.True(r.ExitCode == 0, r.StdErr);
        return r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('|'))
            .ToDictionary(p => p[0], p => p[1], StringComparer.OrdinalIgnoreCase);
    }

    private static string PortableCopy(string folder)
    {
        Directory.CreateDirectory(folder);
        var target = Path.Combine(folder, "portable-browser-" + Guid.NewGuid().ToString("N")[..8] + ".exe");
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "whoami.exe"), target);
        return target;
    }

    [Fact]
    public async Task Standard_user_can_run_windows_and_chrome_but_not_other_browsers_or_portable_copies()
    {
        var user = Environment.GetEnvironmentVariable("FP_TEST_STANDARD_USER");
        Assert.False(string.IsNullOrEmpty(user), "FP_TEST_STANDARD_USER is not set (the CI workflow creates it).");

        var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var chrome = Pf(@"Google\Chrome\Application\chrome.exe");
        var edge = Pf86(@"Microsoft\Edge\Application\msedge.exe");
        var firefox = Pf(@"Mozilla Firefox\firefox.exe");
        var inTemp = PortableCopy(_dir);
        var inWindowsTemp = PortableCopy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "fp-ci"));
        try
        {
            var paths = new[] { notepad, chrome, edge, firefox, inTemp, inWindowsTemp }.Where(File.Exists).ToList();
            Assert.Contains(chrome, paths);
            Assert.Contains(edge, paths);
            var d = await EvaluateAsync(user!, paths);

            Assert.Equal("Allowed", d[notepad]);
            Assert.Equal("Allowed", d[chrome]);
            Assert.Equal("Denied", d[edge]);
            Assert.StartsWith("Denied", d[inTemp], StringComparison.Ordinal);
            Assert.StartsWith("Denied", d[inWindowsTemp], StringComparison.Ordinal);
            if (File.Exists(firefox))
            {
                Assert.StartsWith("Denied", d[firefox], StringComparison.Ordinal);
            }
        }
        finally
        {
            File.Delete(inWindowsTemp);
        }
    }

    [Fact]
    public async Task Administrators_keep_other_tools_but_edge_stays_blocked()
    {
        var admin = Environment.UserName;
        var edge = Pf86(@"Microsoft\Edge\Application\msedge.exe");
        var tool = PortableCopy(_dir);
        var d = await EvaluateAsync(admin, [edge, tool]);
        Assert.Equal("Denied", d[edge]);
        Assert.Equal("Allowed", d[tool]);
    }

    /// <summary>Two installed, non-framework Windows packages ("Name|Publisher"); the build machine has no Store.</summary>
    private static async Task<List<(string Name, string Publisher)>> SystemPackagesAsync()
    {
        var r = await ProcessRunner.RunAsync(ProcessRunner.PowerShell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             "Get-AppxPackage -AllUsers | Where-Object { -not $_.IsFramework -and $_.SignatureKind -eq 'System' } | " +
             "Sort-Object Name -Unique | Select-Object -First 2 | ForEach-Object { \"$($_.Name)|$($_.Publisher)\" }"],
            TimeSpan.FromMinutes(2), CancellationToken.None);
        Assert.True(r.ExitCode == 0, r.StdErr);
        return r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('|')).Select(p => (p[0], p[1])).ToList();
    }

    [Fact]
    public async Task Packaged_app_rule_denies_exactly_the_named_package_for_a_standard_user()
    {
        var user = Environment.GetEnvironmentVariable("FP_TEST_STANDARD_USER");
        Assert.False(string.IsNullOrEmpty(user), "FP_TEST_STANDARD_USER is not set (the CI workflow creates it).");
        var packages = await SystemPackagesAsync();
        Assert.True(packages.Count == 2, "expected at least two installed Windows packages on the build machine");
        var (target, publisher) = packages[0];
        var other = packages[1].Name;

        // Same rules as the Store block, aimed at a package that exists here, evaluated by Windows' engine.
        var xml = Path.Combine(_dir, "appx-policy.xml");
        File.WriteAllText(xml, AppLockerPolicyBuilder.Build(chromeOnly: true, blockStore: true, target, publisher).ToString());
        Assert.Equal("Denied", await AppxPolicyCheck.DecideAsync(xml, target, user, CancellationToken.None));
        Assert.Equal("Allowed", await AppxPolicyCheck.DecideAsync(xml, other, user, CancellationToken.None));
    }

    [Fact]
    public async Task Real_store_policy_keeps_windows_packaged_apps_allowed()
    {
        var user = Environment.GetEnvironmentVariable("FP_TEST_STANDARD_USER");
        Assert.False(string.IsNullOrEmpty(user), "FP_TEST_STANDARD_USER is not set (the CI workflow creates it).");
        var packages = await SystemPackagesAsync();
        Assert.NotEmpty(packages);
        var xml = Path.Combine(_dir, "store-policy.xml");
        File.WriteAllText(xml, AppLockerPolicyBuilder.Build().ToString());
        foreach (var (name, _) in packages)
        {
            Assert.Equal("Allowed", await AppxPolicyCheck.DecideAsync(xml, name, user, CancellationToken.None));
        }
        // The build machine (Windows Server) normally has no Store; where it does, the policy must deny it.
        var store = await AppxPolicyCheck.DecideAsync(xml, AppLockerPolicyBuilder.StorePackageName, user, CancellationToken.None);
        Assert.Contains(store, new[] { AppxPolicyCheck.NotInstalled, "Denied" });
    }
}
