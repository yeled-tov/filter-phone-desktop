using System.Globalization;
using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using RegistryValueKind = Microsoft.Win32.RegistryValueKind;

namespace FilterPhone.Service.Policy;

/// <summary>
/// Ad blocking in Chrome, as the administrator sets it in the dashboard: while "block ads" is on, Chrome policy
/// installs the uBlock Origin Lite extension and hands it the dashboard's exception sites ("noFiltering"). The
/// extension neutralises ad scripts inside the page, so most sites do not detect a blocker (DNS blocking cannot do
/// that, nor exempt a single site — for PCs the server therefore lets the main ad networks through DNS).
///
/// Chrome reads its force-install list as numbered values (1, 2, 3, …) up to the first gap, so our entry goes at
/// the end, and on removal the entries before it are re-packed. We only ever remove what we added: an extension
/// force-installed by someone else, and its settings, are left alone. Everything here is reversible.
/// </summary>
internal static class AdBlockEnforcer
{
    public const string ExtensionId = "ddkjiahejlhfcafbddmgiahcphecmpfh";   // uBlock Origin Lite (Chrome Web Store)
    public const string ForcelistEntry = ExtensionId + ";https://clients2.google.com/service/update2/crx";
    public const string ForcelistKey = MachinePolicies.ChromeKey + @"\ExtensionInstallForcelist";
    public const string ExtensionKey = MachinePolicies.ChromeKey + @"\3rdparty\extensions\" + ExtensionId;
    public const string PolicyKey = ExtensionKey + @"\policy";

    /// <summary>Makes Chrome match the dashboard. Writes only when something differs; run each tick.</summary>
    public static void Apply(MachineState state, ILogger log)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(log);
        if (Choices.BlockAds)
        {
            if (Install(state, Choices.AdAllowSites))
            {
                log.LogInformation("Ad blocking in Chrome is on ({Sites} exception site(s))", Choices.AdAllowSites.Count);
            }
        }
        else if (Remove(state))
        {
            log.LogInformation("Ad blocking in Chrome is off");
        }
    }

    /// <summary>Removes the extension and its settings, if we added them (pause, uninstall).</summary>
    public static void RemoveAll(MachineState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        Remove(state);
    }

    /// <summary>The force-install entries as Chrome reads them: "1", "2", … up to the first missing number.</summary>
    internal static List<string> ReadForcelist()
    {
        using var key = Registry.LocalMachine.OpenSubKey(ForcelistKey);
        var list = new List<string>();
        for (var i = 1; key?.GetValue(Name(i)) is string entry; i++)
        {
            list.Add(entry);
        }
        return list;
    }

    private static string Name(int i) => i.ToString(CultureInfo.InvariantCulture);

    private static bool IsOurs(string entry) =>
        entry.Equals(ExtensionId, StringComparison.OrdinalIgnoreCase)
        || entry.StartsWith(ExtensionId + ";", StringComparison.OrdinalIgnoreCase);

    private static bool Install(MachineState state, IReadOnlyList<string> sites)
    {
        var changed = false;
        var list = ReadForcelist();
        if (!list.Any(IsOurs))
        {
            using var key = Registry.LocalMachine.CreateSubKey(ForcelistKey, writable: true);
            key.SetValue(Name(list.Count + 1), ForcelistEntry, RegistryValueKind.String);
            state.AdBlockForcelistOwned = true;
            state.Save();
            changed = true;
        }
        if (!state.AdBlockForcelistOwned)
        {
            return changed;     // already force-installed by someone else: their settings stay theirs
        }
        return WritePolicy(sites) | changed;
    }

    private static bool WritePolicy(IReadOnlyList<string> sites)
    {
        using var policy = Registry.LocalMachine.CreateSubKey(PolicyKey, writable: true);
        var changed = false;
        if (policy.GetValue("defaultFiltering") as string != "optimal")
        {
            policy.SetValue("defaultFiltering", "optimal", RegistryValueKind.String);
            changed = true;
        }
        if (policy.GetValue("disableFirstRunPage") is not int on || on != 1)
        {
            policy.SetValue("disableFirstRunPage", 1, RegistryValueKind.DWord);
            changed = true;
        }
        using (var current = policy.OpenSubKey("noFiltering"))
        {
            var existing = new List<string>();
            for (var i = 1; current?.GetValue(Name(i)) is string site; i++)
            {
                existing.Add(site);
            }
            if (existing.SequenceEqual(sites, StringComparer.Ordinal) && (current?.ValueCount ?? 0) == sites.Count)
            {
                return changed;
            }
        }
        policy.DeleteSubKeyTree("noFiltering", throwOnMissingSubKey: false);
        if (sites.Count > 0)
        {
            using var list = policy.CreateSubKey("noFiltering", writable: true);
            for (var i = 0; i < sites.Count; i++)
            {
                list.SetValue(Name(i + 1), sites[i], RegistryValueKind.String);
            }
        }
        return true;
    }

    private static bool Remove(MachineState state)
    {
        if (!state.AdBlockForcelistOwned)
        {
            return false;
        }
        var entries = ReadForcelist();
        var remaining = entries.Where(e => !IsOurs(e)).ToList();
        using (var key = Registry.LocalMachine.OpenSubKey(ForcelistKey, writable: true))
        {
            if (key is not null && remaining.Count != entries.Count)
            {
                // Re-pack only the run Chrome reads (1..n); anything after a pre-existing gap is left as it was.
                for (var i = 1; i <= entries.Count; i++)
                {
                    key.DeleteValue(Name(i), throwOnMissingValue: false);
                }
                for (var i = 0; i < remaining.Count; i++)
                {
                    key.SetValue(Name(i + 1), remaining[i], RegistryValueKind.String);
                }
            }
        }
        Registry.LocalMachine.DeleteSubKeyTree(ExtensionKey, throwOnMissingSubKey: false);
        state.AdBlockForcelistOwned = false;
        state.Save();
        return true;
    }
}
