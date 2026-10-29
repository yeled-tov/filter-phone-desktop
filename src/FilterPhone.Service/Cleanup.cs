using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Network;
using FilterPhone.Service.Policy;
using FilterPhone.Service.Trust;
using FilterPhone.Service.Tunnel;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service;

/// <summary>
/// Restores what this product changed, and nothing else (used by the uninstaller and for recovery).
/// Order matters: the network lock is removed first so a failure later never leaves the PC offline.
/// On an activated PC this needs a removal code from the dashboard first (see RemovalGate).
/// </summary>
internal static class Cleanup
{
    public const int RemovalCodeRequired = 5;

    public static async Task<int> RunAsync(ILoggerFactory loggers, bool networkLockOnly)
    {
        var log = loggers.CreateLogger("Cleanup");
        if (!RemovalGate.Allowed(MachineState.Load(), DateTimeOffset.UtcNow))
        {
            log.LogWarning("Removal refused: a removal code from the FilterPhone dashboard is required");
            Console.Error.WriteLine("A removal code from FilterPhone is required. Run: FilterPhone.Service.exe --authorize-removal CODE");
            return RemovalCodeRequired;
        }
        var failures = 0;

        failures += Step(log, "network lock", WfpKillSwitch.Remove);
        if (networkLockOnly)
        {
            return failures == 0 ? 0 : 1;
        }

        var state = MachineState.Load();
        failures += await StepAsync(log, "tunnel service",
            () => new TunnelController(loggers.CreateLogger<TunnelController>()).UninstallAsync(CancellationToken.None)).ConfigureAwait(false);
        failures += Step(log, "filtering CA",
            () => new TrustStore(loggers.CreateLogger<TrustStore>()).Remove(state.TrustedCaThumbprints));
        failures += await StepAsync(log, "browser restriction",
            () => new ChromeOnlyEnforcer(loggers.CreateLogger<ChromeOnlyEnforcer>()).RemoveAsync(state, CancellationToken.None)).ConfigureAwait(false);
        failures += Step(log, "secrets and state", () =>
        {
            SecretStore.DeleteAll();
            foreach (var f in new[] { Paths.TunnelConfig, Paths.StateFile, Paths.AppLockerPolicyFile, Paths.ProbeExecutable })
            {
                if (File.Exists(f))
                {
                    File.Delete(f);
                }
            }
        });
        log.LogInformation("Cleanup finished with {Failures} failed step(s)", failures);
        return failures == 0 ? 0 : 1;
    }

    private static int Step(ILogger log, string name, Action action)
    {
        try
        {
            action();
            log.LogInformation("Removed: {Step}", name);
            return 0;
        }
        catch (Exception e)
        {
            log.LogError(e, "Could not remove: {Step}", name);
            return 1;
        }
    }

    private static async Task<int> StepAsync(ILogger log, string name, Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            log.LogInformation("Removed: {Step}", name);
            return 0;
        }
        catch (Exception e)
        {
            log.LogError(e, "Could not remove: {Step}", name);
            return 1;
        }
    }
}
