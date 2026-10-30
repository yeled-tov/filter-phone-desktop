using FilterPhone.Core.Api;
using FilterPhone.Core.Policy;
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

    /// <summary>An optional Windows toggle (block_copilot, …): off unless the dashboard turned it on.</summary>
    public static bool Extra(string name) => ReadBool(name, defaultValue: false);

    /// <summary>Stores the dashboard's values. Returns true when something changed.</summary>
    public static bool Save(DesktopControls controls)
    {
        ArgumentNullException.ThrowIfNull(controls);
        using var key = Registry.LocalMachine.CreateSubKey(ServerKey, writable: true);
        var changed = false;
        void Put(string name, bool on)
        {
            var value = on ? 1 : 0;
            if (key.GetValue(name) is not int current || current != value)
            {
                key.SetValue(name, value, Microsoft.Win32.RegistryValueKind.DWord);
                changed = true;
            }
        }
        Put("ChromeOnly", controls.ChromeOnly);
        Put("BlockStore", controls.BlockStore);
        foreach (var name in DesktopControls.ExtraNames)
        {
            Put(name, controls.Extra(name));
        }
        return changed;
    }

    /// <summary>Missing = allowed (the installer's consent alone decides until the dashboard says otherwise).</summary>
    private static bool ServerAllows(string name) => ReadBool(name, defaultValue: true);

    private static bool ReadBool(string name, bool defaultValue)
    {
        using var key = Registry.LocalMachine.OpenSubKey(ServerKey);
        return key?.GetValue(name) is int v ? v != 0 : defaultValue;
    }
}
