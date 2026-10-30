using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Policy;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

namespace FilterPhone.Windows.Tests;

/// <summary>
/// Proves that an optional Windows toggle (block_copilot) is applied as its Group Policy registry value when
/// the dashboard turns it on, and the original value is restored exactly when it is turned off — on the real
/// registry. Uses a harmless, fully reversible policy key and cleans up after itself.
/// </summary>
public sealed class DesktopExtrasTests : IDisposable
{
    private readonly PolicyValue _copilot = MachinePolicies.DesktopExtras["block_copilot"][0];

    public DesktopExtrasTests() => SecureDirectory.EnsureAll();

    public void Dispose()
    {
        // Remove the dashboard choice and any value we might have left.
        using (var server = Registry.LocalMachine.OpenSubKey(Choices.ServerKey, writable: true))
        {
            server?.DeleteValue("block_copilot", throwOnMissingValue: false);
        }
        using var key = Registry.LocalMachine.OpenSubKey(_copilot.KeyPath, writable: true);
        key?.DeleteValue(_copilot.Name, throwOnMissingValue: false);
    }

    private static void SetChoice(bool on)
    {
        using var server = Registry.LocalMachine.CreateSubKey(Choices.ServerKey, writable: true);
        server.SetValue("block_copilot", on ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
    }

    private int? Current()
    {
        using var key = Registry.LocalMachine.OpenSubKey(_copilot.KeyPath);
        return key?.GetValue(_copilot.Name) as int?;
    }

    [Fact]
    public void Optional_toggle_is_applied_when_on_and_restored_exactly_when_off()
    {
        var state = new MachineState();

        // Off by default: nothing is written.
        SetChoice(false);
        DesktopExtrasEnforcer.Apply(state, NullLogger.Instance);
        Assert.Null(Current());

        // Turned on in the dashboard: the policy value is set.
        SetChoice(true);
        DesktopExtrasEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(1, Current());
        Assert.Contains(state.DesktopExtraBackup.Keys, k => k.Contains("TurnOffWindowsCopilot", StringComparison.Ordinal));

        // Idempotent: applying again changes nothing.
        DesktopExtrasEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(1, Current());

        // Turned off again: the original (absent) value is restored, and the backup is cleared.
        SetChoice(false);
        DesktopExtrasEnforcer.Apply(state, NullLogger.Instance);
        Assert.Null(Current());
        Assert.Empty(state.DesktopExtraBackup);
    }

    [Fact]
    public void RemoveAll_restores_a_pre_existing_value()
    {
        var state = new MachineState();
        using (var key = Registry.LocalMachine.CreateSubKey(_copilot.KeyPath, writable: true))
        {
            key.SetValue(_copilot.Name, 0, Microsoft.Win32.RegistryValueKind.DWord);   // the user had it explicitly off
        }
        SetChoice(true);
        DesktopExtrasEnforcer.Apply(state, NullLogger.Instance);
        Assert.Equal(1, Current());

        DesktopExtrasEnforcer.RemoveAll(state);
        Assert.Equal(0, Current());                                    // exactly what was there before
        Assert.Empty(state.DesktopExtraBackup);
    }
}
