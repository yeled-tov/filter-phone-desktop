using System.ComponentModel;
using System.ServiceProcess;
using System.Text;
using FilterPhone.Core;
using FilterPhone.Core.Vpn;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Tunnel;

public sealed class TunnelException(string code, string? detail = null) : Exception($"{code}: {detail}")
{
    public string Code { get; } = code;
}

internal sealed record TunnelStatus(bool Installed, bool Running, DateTimeOffset? LatestHandshake, long RxBytes, long TxBytes);

/// <summary>
/// Drives the official WireGuard for Windows tunnel service (docs/enterprise.md):
///   wireguard.exe /installtunnelservice C:\...\FilterPhone.conf.dpapi  → service WireGuardTunnel$FilterPhone
/// The configuration is written as a DPAPI-encrypted .conf.dpapi file (LocalSystem key, description =
/// tunnel name, exactly as WireGuard's own manager does) in a SYSTEM/Administrators-only folder, so the
/// private key never exists in plain text on disk and is never passed on a command line.
/// wireguard.exe and wg.exe are only executed after their Authenticode signature is verified as WireGuard LLC.
/// </summary>
internal sealed class TunnelController(ILogger<TunnelController> log)
{
    public const string Name = ProductConfig.TunnelName;
    public static string ServiceName => "WireGuardTunnel$" + Name;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    public static bool WireGuardInstalled => File.Exists(Paths.WireGuardExe) && File.Exists(Paths.WgExe);

    public void WriteConfig(string config)
    {
        var bytes = Encoding.UTF8.GetBytes(config);
        try
        {
            SecureDirectory.WriteAllBytesAtomic(Paths.TunnelConfig, Dpapi.Protect(bytes, Name));
        }
        finally
        {
            Array.Clear(bytes);
        }
        log.LogInformation("Tunnel configuration written (DPAPI-protected)");
    }

    public static bool IsInstalled()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            _ = sc.Status;
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public async Task InstallAsync(CancellationToken ct)
    {
        VerifyBinaries();
        if (IsInstalled())
        {
            return;
        }
        var r = await ProcessRunner.RunAsync(Paths.WireGuardExe, ["/installtunnelservice", Paths.TunnelConfig], CommandTimeout, ct)
            .ConfigureAwait(false);
        if (r.ExitCode != 0 || !IsInstalled())
        {
            throw new TunnelException("install_failed", Trim(r.StdErr + r.StdOut));
        }
        await ConfigureRecoveryAsync(ct).ConfigureAwait(false);
        log.LogInformation("WireGuard tunnel service installed");
    }

    /// <summary>Automatic start and restart-on-failure for the tunnel service (idempotent).</summary>
    public async Task ConfigureRecoveryAsync(CancellationToken ct)
    {
        var sc = Path.Combine(Paths.System32, "sc.exe");
        await ProcessRunner.RunAsync(sc, ["config", ServiceName, "start=", "auto"], CommandTimeout, ct).ConfigureAwait(false);
        await ProcessRunner.RunAsync(sc, ["failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000"],
            CommandTimeout, ct).ConfigureAwait(false);
        await ProcessRunner.RunAsync(sc, ["failureflag", ServiceName, "1"], CommandTimeout, ct).ConfigureAwait(false);
        log.LogInformation("Tunnel service set to start automatically and restart on failure");
    }

    public async Task UninstallAsync(CancellationToken ct)
    {
        if (!IsInstalled())
        {
            return;
        }
        if (File.Exists(Paths.WireGuardExe))
        {
            VerifyBinaries();
            await ProcessRunner.RunAsync(Paths.WireGuardExe, ["/uninstalltunnelservice", Name], CommandTimeout, ct).ConfigureAwait(false);
        }
        log.LogInformation("WireGuard tunnel service removed");
    }

    public void Start()
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
        {
            return;
        }
        log.LogInformation("Starting the tunnel service");
        try
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            throw new TunnelException("start_timeout");
        }
        catch (InvalidOperationException e) when (e.InnerException is Win32Exception w)
        {
            throw new TunnelException("start_failed", $"win32 {w.NativeErrorCode}");
        }
    }

    /// <summary>Restart to apply a new configuration. The network lock stays in place throughout.</summary>
    public void Restart()
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
        {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
        }
        Start();
    }

    public static async Task<TunnelStatus> QueryAsync(CancellationToken ct)
    {
        if (!IsInstalled())
        {
            return new TunnelStatus(false, false, null, 0, 0);
        }
        bool running;
        using (var sc = new ServiceController(ServiceName))
        {
            running = sc.Status == ServiceControllerStatus.Running;
        }
        if (!running)
        {
            return new TunnelStatus(true, false, null, 0, 0);
        }
        VerifyWg();
        var hs = await ProcessRunner.RunAsync(Paths.WgExe, ["show", Name, "latest-handshakes"], CommandTimeout, ct).ConfigureAwait(false);
        var tr = await ProcessRunner.RunAsync(Paths.WgExe, ["show", Name, "transfer"], CommandTimeout, ct).ConfigureAwait(false);
        if (hs.ExitCode != 0)
        {
            return new TunnelStatus(true, true, null, 0, 0);
        }
        var handshakes = WgShowParser.ParseLatestHandshakes(hs.StdOut);
        var transfer = WgShowParser.ParseTransfer(tr.StdOut);
        var latest = handshakes.Values.Where(v => v is not null).Max();
        var rx = transfer.Values.Sum(t => t.Rx);
        var tx = transfer.Values.Sum(t => t.Tx);
        return new TunnelStatus(true, true, latest, rx, tx);
    }

    private static void VerifyBinaries()
    {
        if (!SignatureVerifier.IsTrusted(Paths.WireGuardExe, SignatureVerifier.WireGuardPublisher, out var why))
        {
            throw new TunnelException("wireguard_not_trusted", why);
        }
        VerifyWg();
    }

    private static void VerifyWg()
    {
        if (!SignatureVerifier.IsTrusted(Paths.WgExe, SignatureVerifier.WireGuardPublisher, out var why))
        {
            throw new TunnelException("wireguard_not_trusted", why);
        }
    }

    private static string Trim(string s) => s.Length <= 200 ? s.Trim() : s[..200].Trim();
}
