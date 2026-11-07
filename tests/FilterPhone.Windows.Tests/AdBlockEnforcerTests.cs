using System.Globalization;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Policy;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

namespace FilterPhone.Windows.Tests;

/// <summary>
/// The ad-blocking extension is added to Chrome's numbered force-install list without disturbing another
/// extension already there, gets the dashboard's exception sites, and is removed cleanly — on the real registry.
/// Every key it touches is restored afterwards. In the "wfp" collection because it saves the machine state file.
/// </summary>
[Collection("wfp")]
public sealed class AdBlockEnforcerTests : IDisposable
{
    private const string Other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://example.invalid/update";
    private readonly Dictionary<string, object> _forcelistBackup = [];
    private readonly byte[]? _stateBackup;

    public AdBlockEnforcerTests()
    {
        Directory.CreateDirectory(Paths.DataRoot);
        _stateBackup = File.Exists(Paths.StateFile) ? File.ReadAllBytes(Paths.StateFile) : null;
        using var key = Registry.LocalMachine.OpenSubKey(AdBlockEnforcer.ForcelistKey);
        foreach (var name in key?.GetValueNames() ?? [])
        {
            _forcelistBackup[name] = key!.GetValue(name)!;
        }
        Registry.LocalMachine.DeleteSubKeyTree(AdBlockEnforcer.ForcelistKey, throwOnMissingSubKey: false);
    }

    public void Dispose()
    {
        Registry.LocalMachine.DeleteSubKeyTree(AdBlockEnforcer.ForcelistKey, throwOnMissingSubKey: false);
        if (_forcelistBackup.Count > 0)
        {
            using var key = Registry.LocalMachine.CreateSubKey(AdBlockEnforcer.ForcelistKey, writable: true);
            foreach (var (name, value) in _forcelistBackup)
            {
                key.SetValue(name, value);
            }
        }
        Registry.LocalMachine.DeleteSubKeyTree(AdBlockEnforcer.ExtensionKey, throwOnMissingSubKey: false);
        using (var server = Registry.LocalMachine.OpenSubKey(Choices.ServerKey, writable: true))
        {
            server?.DeleteValue("BlockAds", throwOnMissingValue: false);
            server?.DeleteValue("AdAllowSites", throwOnMissingValue: false);
        }
        if (_stateBackup is null)
        {
            File.Delete(Paths.StateFile);
        }
        else
        {
            File.WriteAllBytes(Paths.StateFile, _stateBackup);
        }
    }

    private static void Dashboard(bool blockAds, params string[] sites)
    {
        using var server = Registry.LocalMachine.CreateSubKey(Choices.ServerKey, writable: true);
        server.SetValue("BlockAds", blockAds ? 1 : 0, RegistryValueKind.DWord);
        server.SetValue("AdAllowSites", sites, RegistryValueKind.MultiString);
    }

    private static void SetForcelist(params string[] entries)
    {
        using var key = Registry.LocalMachine.CreateSubKey(AdBlockEnforcer.ForcelistKey, writable: true);
        for (var i = 0; i < entries.Length; i++)
        {
            key.SetValue((i + 1).ToString(CultureInfo.InvariantCulture), entries[i]);
        }
    }

    private static string[] NoFiltering()
    {
        using var key = Registry.LocalMachine.OpenSubKey(AdBlockEnforcer.PolicyKey + @"\noFiltering");
        return key is null ? [] : key.GetValueNames().OrderBy(n => int.Parse(n, CultureInfo.InvariantCulture)).Select(n => (string)key.GetValue(n)!).ToArray();
    }

    [Fact]
    public void Installs_after_existing_extensions_with_exception_sites_and_removes_cleanly()
    {
        SetForcelist(Other);
        var state = new MachineState();
        Dashboard(blockAds: true, "news.example", "shop.example");

        AdBlockEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(new[] { Other, AdBlockEnforcer.ForcelistEntry }, AdBlockEnforcer.ReadForcelist());
        Assert.True(state.AdBlockForcelistOwned);
        Assert.Equal(new[] { "news.example", "shop.example" }, NoFiltering());
        using (var policy = Registry.LocalMachine.OpenSubKey(AdBlockEnforcer.PolicyKey))
        {
            Assert.Equal("optimal", policy!.GetValue("defaultFiltering"));
        }

        AdBlockEnforcer.Apply(state, NullLogger.Instance);     // idempotent: still one entry of ours
        Assert.Equal(2, AdBlockEnforcer.ReadForcelist().Count);

        Dashboard(blockAds: true, "shop.example");               // the exception list follows the dashboard
        AdBlockEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(new[] { "shop.example" }, NoFiltering());

        Dashboard(blockAds: false);
        AdBlockEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(new[] { Other }, AdBlockEnforcer.ReadForcelist());  // the other extension is untouched
        Assert.False(state.AdBlockForcelistOwned);
        Assert.Null(Registry.LocalMachine.OpenSubKey(AdBlockEnforcer.ExtensionKey));
    }

    [Fact]
    public void Never_removes_or_reconfigures_an_extension_someone_else_installed()
    {
        SetForcelist(AdBlockEnforcer.ForcelistEntry);
        var state = new MachineState();
        Dashboard(blockAds: true, "news.example");
        AdBlockEnforcer.Apply(state, NullLogger.Instance);
        Assert.False(state.AdBlockForcelistOwned);
        Assert.Null(Registry.LocalMachine.OpenSubKey(AdBlockEnforcer.PolicyKey));

        Dashboard(blockAds: false);
        AdBlockEnforcer.Apply(state, NullLogger.Instance);
        AdBlockEnforcer.RemoveAll(state);
        Assert.Equal(new[] { AdBlockEnforcer.ForcelistEntry }, AdBlockEnforcer.ReadForcelist());
    }
}
