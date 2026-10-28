using System.Globalization;
using System.ServiceProcess;
using FilterPhone.Core.Policy;
using FilterPhone.Core.Status;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace FilterPhone.Service.Policy;

internal sealed record PolicyResult(CheckState State, string Code);

/// <summary>
/// Makes Google Chrome the only browser by Windows application control (AppLocker), applies the Chrome
/// machine policies, and proves enforcement with <see cref="LaunchProbe"/>. If enforcement cannot be proven on
/// this Windows edition, the result is "unsupported" (shown to the user as a limitation), never "ok".
/// It never removes Edge or other software and never overwrites an AppLocker policy it did not create.
/// </summary>
internal sealed class ChromeOnlyEnforcer(ILogger<ChromeOnlyEnforcer> log)
{
    private const string CspParent = "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/FilterPhone";
    private static readonly TimeSpan PsTimeout = TimeSpan.FromMinutes(2);

    public static string? FindChrome()
    {
        using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"))
        {
            if (key?.GetValue(null) is string p && File.Exists(p.Trim('"')))
            {
                return p.Trim('"');
            }
        }
        return new[]
        {
            Path.Combine(Paths.ProgramFiles, @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Paths.ProgramFilesX86, @"Google\Chrome\Application\chrome.exe"),
        }.FirstOrDefault(File.Exists);
    }

    public static string? FindEdge() => new[]
    {
        Path.Combine(Paths.ProgramFilesX86, @"Microsoft\Edge\Application\msedge.exe"),
        Path.Combine(Paths.ProgramFiles, @"Microsoft\Edge\Application\msedge.exe"),
    }.FirstOrDefault(File.Exists);

    /// <summary>Applies (idempotently) the Chrome policies and, where possible, the AppLocker policy.</summary>
    public async Task<PolicyResult> ApplyAsync(MachineState state, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!Consent.ChromeOnly)
        {
            return new PolicyResult(CheckState.Failed, "consent_missing");
        }
        ApplyMachinePolicies(state);
        if (WindowsInfo.AppControl == AppControlSupport.Unsupported)
        {
            return new PolicyResult(CheckState.Unsupported, "edition_unsupported");
        }
        if (FindChrome() is null)
        {
            // Without Chrome the policy would leave the user without any browser.
            return new PolicyResult(CheckState.Failed, "chrome_missing");
        }
        if (state.AppLockerMode is "local" or "csp")
        {
            return new PolicyResult(CheckState.Pending, "applied");
        }

        var current = await GetLocalPolicyAsync(ct).ConfigureAwait(false);
        if (AppLockerPolicyBuilder.HasExecutableRules(current) && !AppLockerPolicyBuilder.IsOurs(current))
        {
            return new PolicyResult(CheckState.Failed, "foreign_applocker_policy");
        }

        EnsureAppIdService(state);
        File.WriteAllText(Paths.AppLockerPolicyFile, AppLockerPolicyBuilder.Build().ToString());
        var r = await PowerShellAsync($"Import-Module AppLocker; Set-AppLockerPolicy -XmlPolicy '{Paths.AppLockerPolicyFile}'", ct)
            .ConfigureAwait(false);
        if (r.ExitCode != 0)
        {
            log.LogWarning("Set-AppLockerPolicy failed: {Err}", r.StdErr);
            return new PolicyResult(CheckState.Failed, "applocker_apply_failed");
        }
        await GpUpdateAsync(ct).ConfigureAwait(false);
        state.AppLockerMode = "local";
        state.Save();
        log.LogInformation("AppLocker Chrome-only policy applied (local policy, edition {Edition})", WindowsInfo.EditionId);
        return new PolicyResult(CheckState.Pending, "applied");
    }

    /// <summary>Real enforcement check for the signed-in user. Escalates Pro editions to the CSP if needed.</summary>
    public async Task<PolicyResult> VerifyAsync(MachineState state, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (WindowsInfo.AppControl == AppControlSupport.Unsupported)
        {
            return new PolicyResult(CheckState.Unsupported, "edition_unsupported");
        }
        if (state.AppLockerMode is null)
        {
            return new PolicyResult(CheckState.Pending, "not_applied");
        }
        var chrome = FindChrome();
        if (chrome is null)
        {
            return new PolicyResult(CheckState.Failed, "chrome_missing");
        }
        EnsureProbeExecutable();
        var chromeResult = LaunchProbe.Try(chrome);
        var portable = LaunchProbe.Try(Paths.ProbeExecutable);
        var edge = FindEdge() is string e ? LaunchProbe.Try(e) : LaunchResult.NotFound;
        log.LogInformation("Launch probe: chrome={Chrome} edge={Edge} portable={Portable}", chromeResult, edge, portable);

        if (chromeResult == LaunchResult.NoUserSession)
        {
            return new PolicyResult(CheckState.Pending, "no_user_session");
        }
        if (chromeResult != LaunchResult.Allowed)
        {
            return new PolicyResult(CheckState.Failed, "chrome_blocked");
        }
        var enforced = portable == LaunchResult.BlockedByPolicy && (edge is LaunchResult.BlockedByPolicy or LaunchResult.NotFound);
        if (enforced)
        {
            return new PolicyResult(CheckState.Ok, "enforced");
        }
        if (WindowsInfo.AppControl == AppControlSupport.ProWithVerification && state.AppLockerMode == "local")
        {
            // Local AppLocker policy is not enforced on this Pro installation: use the AppLocker CSP instead.
            if (await ApplyCspAsync(ct).ConfigureAwait(false))
            {
                state.AppLockerMode = "csp";
                state.Save();
                return new PolicyResult(CheckState.Pending, "applied_csp");
            }
        }
        return new PolicyResult(CheckState.Unsupported, "not_enforced_on_this_windows");
    }

    /// <summary>Removes only what this product applied (uninstall).</summary>
    public async Task RemoveAsync(MachineState state, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(state);
        var current = await GetLocalPolicyAsync(ct).ConfigureAwait(false);
        if (AppLockerPolicyBuilder.IsOurs(current))
        {
            var empty = Path.Combine(Paths.DataRoot, "applocker-empty.xml");
            File.WriteAllText(empty, AppLockerPolicyBuilder.Empty().ToString());
            await PowerShellAsync($"Import-Module AppLocker; Set-AppLockerPolicy -XmlPolicy '{empty}'", ct).ConfigureAwait(false);
            await GpUpdateAsync(ct).ConfigureAwait(false);
        }
        if (state.AppLockerMode == "csp")
        {
            await PowerShellAsync(
                "$ns='root\\cimv2\\mdm\\dmmap'; $c='MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03'; " +
                $"Get-CimInstance -Namespace $ns -ClassName $c -Filter \"ParentID='{CspParent}' and InstanceID='EXE'\" | Remove-CimInstance", ct)
                .ConfigureAwait(false);
        }
        state.AppLockerMode = null;
        RestoreMachinePolicies(state);
        if (state.AppIdSvcOriginalStart is int start)
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\AppIDSvc", writable: true);
            key?.SetValue("Start", start, Microsoft.Win32.RegistryValueKind.DWord);
            state.AppIdSvcOriginalStart = null;
        }
        state.Save();
        log.LogInformation("Browser restriction and Chrome policies removed");
    }

    private async Task<bool> ApplyCspAsync(CancellationToken ct)
    {
        var fragment = Path.Combine(Paths.DataRoot, "applocker-exe.xml");
        File.WriteAllText(fragment, AppLockerPolicyBuilder.ExeCollectionXml());
        var r = await PowerShellAsync(
            "$ns='root\\cimv2\\mdm\\dmmap'; $c='MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03'; " +
            $"$p='{CspParent}'; " +
            $"$x=[System.Net.WebUtility]::HtmlEncode([IO.File]::ReadAllText('{fragment}')); " +
            "Get-CimInstance -Namespace $ns -ClassName $c -Filter \"ParentID='$p' and InstanceID='EXE'\" | Remove-CimInstance; " +
            "New-CimInstance -Namespace $ns -ClassName $c -Property @{ParentID=$p;InstanceID='EXE';Policy=$x} | Out-Null", ct)
            .ConfigureAwait(false);
        if (r.ExitCode != 0)
        {
            log.LogWarning("AppLocker CSP apply failed: {Err}", r.StdErr);
            return false;
        }
        log.LogInformation("AppLocker Chrome-only policy applied through the AppLocker CSP");
        return true;
    }

    private static async Task<string?> GetLocalPolicyAsync(CancellationToken ct)
    {
        var r = await PowerShellAsync("Import-Module AppLocker; Get-AppLockerPolicy -Local -Xml", ct).ConfigureAwait(false);
        return r.ExitCode == 0 ? r.StdOut.Trim() : null;
    }

    private static Task<ProcessResult> PowerShellAsync(string command, CancellationToken ct) =>
        ProcessRunner.RunAsync(ProcessRunner.PowerShell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command], PsTimeout, ct);

    private static Task<ProcessResult> GpUpdateAsync(CancellationToken ct) =>
        ProcessRunner.RunAsync(Path.Combine(Paths.System32, "gpupdate.exe"), ["/target:computer", "/force"], PsTimeout, ct);

    private void EnsureAppIdService(MachineState state)
    {
        // AppLocker executable rules are enforced only while the Application Identity service runs.
        using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\AppIDSvc", writable: true))
        {
            if (key is null)
            {
                throw new InvalidOperationException("Application Identity service is not present.");
            }
            var start = key.GetValue("Start") as int? ?? 3;
            if (start != 2)
            {
                state.AppIdSvcOriginalStart ??= start;
                key.SetValue("Start", 2, Microsoft.Win32.RegistryValueKind.DWord);
                state.Save();
            }
        }
        using var sc = new ServiceController("AppIDSvc");
        if (sc.Status != ServiceControllerStatus.Running)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            log.LogInformation("Application Identity service started");
        }
    }

    private static void EnsureProbeExecutable()
    {
        // A harmless signed Windows binary copied to a non-allowed folder stands in for a portable browser.
        var source = Path.Combine(Paths.System32, "whoami.exe");
        if (!File.Exists(Paths.ProbeExecutable) || new FileInfo(Paths.ProbeExecutable).Length != new FileInfo(source).Length)
        {
            File.Copy(source, Paths.ProbeExecutable, overwrite: true);
        }
    }

    private static void ApplyMachinePolicies(MachineState state)
    {
        File.WriteAllText(Paths.DefaultAssociationsFile, MachinePolicies.DefaultAssociations().ToString());
        foreach (var v in MachinePolicies.Chrome.Concat(MachinePolicies.Windows(Paths.DefaultAssociationsFile)))
        {
            using var key = Registry.LocalMachine.CreateSubKey(v.KeyPath, writable: true);
            var id = v.KeyPath + "|" + v.Name;
            if (!state.PolicyBackup.ContainsKey(id))
            {
                state.PolicyBackup[id] = key.GetValue(v.Name) is { } old ? Convert.ToString(old, CultureInfo.InvariantCulture) : null;
            }
            if (v.Kind == Core.Policy.RegistryValueKind.DWord)
            {
                key.SetValue(v.Name, Convert.ToInt32(v.Value, CultureInfo.InvariantCulture), Microsoft.Win32.RegistryValueKind.DWord);
            }
            else
            {
                key.SetValue(v.Name, (string)v.Value, Microsoft.Win32.RegistryValueKind.String);
            }
        }
        state.Save();
    }

    public static bool MachinePoliciesApplied()
    {
        foreach (var v in MachinePolicies.Chrome)
        {
            using var key = Registry.LocalMachine.OpenSubKey(v.KeyPath);
            var current = key?.GetValue(v.Name);
            if (current is null || Convert.ToString(current, CultureInfo.InvariantCulture) != Convert.ToString(v.Value, CultureInfo.InvariantCulture))
            {
                return false;
            }
        }
        return true;
    }

    private static void RestoreMachinePolicies(MachineState state)
    {
        foreach (var v in MachinePolicies.Chrome.Concat(MachinePolicies.Windows(Paths.DefaultAssociationsFile)))
        {
            var id = v.KeyPath + "|" + v.Name;
            using var key = Registry.LocalMachine.OpenSubKey(v.KeyPath, writable: true);
            if (key is null)
            {
                continue;
            }
            if (state.PolicyBackup.TryGetValue(id, out var old) && old is not null)
            {
                if (v.Kind == Core.Policy.RegistryValueKind.DWord && int.TryParse(old, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
                {
                    key.SetValue(v.Name, n, Microsoft.Win32.RegistryValueKind.DWord);
                }
                else
                {
                    key.SetValue(v.Name, old, Microsoft.Win32.RegistryValueKind.String);
                }
            }
            else
            {
                key.DeleteValue(v.Name, throwOnMissingValue: false);
            }
        }
        state.PolicyBackup.Clear();
        try
        {
            File.Delete(Paths.DefaultAssociationsFile);
        }
        catch (IOException)
        {
        }
    }
}
