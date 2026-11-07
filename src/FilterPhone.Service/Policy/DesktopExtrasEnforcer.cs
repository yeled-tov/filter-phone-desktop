using System.Globalization;
using FilterPhone.Core.Api;
using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using CoreRegistryValueKind = FilterPhone.Core.Policy.RegistryValueKind;

namespace FilterPhone.Service.Policy;

/// <summary>
/// Applies the optional Windows blocks the administrator turns on in the dashboard (Copilot, widgets,
/// lock-screen Spotlight, Start-menu web search, removable storage). Each is a standard Group Policy registry
/// value: it is set only while its toggle is on, and the original value is restored the moment it is turned
/// off or the product is removed. Nothing here is forced — every toggle is off by default and reversible.
/// </summary>
internal static class DesktopExtrasEnforcer
{
    /// <summary>Makes the registry match the dashboard's current choices. Cheap and idempotent; run each tick.</summary>
    public static void Apply(MachineState state, ILogger log)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(log);
        var changed = false;
        foreach (var (name, values) in MachinePolicies.DesktopExtras)
        {
            var wanted = Choices.Extra(name);
            foreach (var v in values)
            {
                changed |= wanted ? Set(state, v) : Restore(state, v);
            }
        }
        if (changed)
        {
            state.Save();
        }
    }

    /// <summary>Restores every value these toggles touched (uninstall / full cleanup).</summary>
    public static void RemoveAll(MachineState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        foreach (var values in MachinePolicies.DesktopExtras.Values)
        {
            foreach (var v in values)
            {
                Restore(state, v);
            }
        }
        state.DesktopExtraBackup.Clear();
    }

    private static string Id(PolicyValue v) => v.KeyPath + "|" + v.Name;

    private static bool Set(MachineState state, PolicyValue v)
    {
        using var key = Registry.LocalMachine.CreateSubKey(v.KeyPath, writable: true);
        var current = key.GetValue(v.Name);
        if (current is not null && Convert.ToString(current, CultureInfo.InvariantCulture) == Convert.ToString(v.Value, CultureInfo.InvariantCulture)
            && state.DesktopExtraBackup.ContainsKey(Id(v)))
        {
            return false;   // already set by us
        }
        if (!state.DesktopExtraBackup.ContainsKey(Id(v)))
        {
            state.DesktopExtraBackup[Id(v)] = current is { } old ? Convert.ToString(old, CultureInfo.InvariantCulture) : null;
        }
        Write(key, v);
        return true;
    }

    private static bool Restore(MachineState state, PolicyValue v)
    {
        if (!state.DesktopExtraBackup.Remove(Id(v), out var old))
        {
            return false;   // we never set it
        }
        using var key = Registry.LocalMachine.OpenSubKey(v.KeyPath, writable: true);
        if (key is null)
        {
            return true;
        }
        if (old is null)
        {
            key.DeleteValue(v.Name, throwOnMissingValue: false);
        }
        else if (v.Kind == CoreRegistryValueKind.DWord && int.TryParse(old, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
        {
            key.SetValue(v.Name, n, Microsoft.Win32.RegistryValueKind.DWord);
        }
        else
        {
            key.SetValue(v.Name, old, Microsoft.Win32.RegistryValueKind.String);
        }
        return true;
    }

    private static void Write(RegistryKey key, PolicyValue v)
    {
        if (v.Kind == CoreRegistryValueKind.DWord)
        {
            key.SetValue(v.Name, Convert.ToInt32(v.Value, CultureInfo.InvariantCulture), Microsoft.Win32.RegistryValueKind.DWord);
        }
        else
        {
            key.SetValue(v.Name, (string)v.Value, Microsoft.Win32.RegistryValueKind.String);
        }
    }
}
