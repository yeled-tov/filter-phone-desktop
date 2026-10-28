using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;

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
}
