using FilterPhone.Core.Api;
using Microsoft.Win32;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// What is actually enforced: a restriction runs only if the administrator consented to it in the installer
/// AND the dashboard has it on. The dashboard can therefore turn a consented restriction off and back on, but
/// never impose one the administrator of this PC did not agree to. The dashboard's values arrive with each
/// heartbeat and are kept in HKLM (administrators only), so they also apply while the PC is offline.
/// </summary>
internal static class Choices
{
    public const string ServerKey = @"SOFTWARE\FilterPhone Desktop\Server";

    public static bool ChromeOnly => Consent.ChromeOnly && ServerAllows("ChromeOnly");
    public static bool BlockStore => Consent.BlockStore && ServerAllows("BlockStore");

    /// <summary>Stores the dashboard's values. Returns true when something changed.</summary>
    public static bool Save(DesktopControls controls)
    {
        ArgumentNullException.ThrowIfNull(controls);
        using var key = Registry.LocalMachine.CreateSubKey(ServerKey, writable: true);
        var changed = false;
        foreach (var (name, on) in new[] { ("ChromeOnly", controls.ChromeOnly), ("BlockStore", controls.BlockStore) })
        {
            var value = on ? 1 : 0;
            if (key.GetValue(name) is not int current || current != value)
            {
                key.SetValue(name, value, RegistryValueKind.DWord);
                changed = true;
            }
        }
        return changed;
    }

    /// <summary>Missing = allowed (the installer's consent alone decides until the dashboard says otherwise).</summary>
    private static bool ServerAllows(string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(ServerKey);
        return key?.GetValue(name) is not int v || v != 0;
    }
}
