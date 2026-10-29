using System.Diagnostics;
using System.Runtime.InteropServices;
using FilterPhone.Core.Policy;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Native;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Policy;

/// <summary>What the watchdog learns about one running process (used by its decision predicate).</summary>
internal sealed record ProcessSnapshot(int Pid, string? Path, string? ProductName, string? CompanyName, string FileName);

/// <summary>
/// The Windows analogue of the Android accessibility guard: a fast loop (every ~1.5 s) that terminates any
/// disallowed browser the moment it appears, even if it managed to launch. This is the primary browser
/// enforcement on Windows Home (where AppLocker is unavailable) and a second layer everywhere else.
///
/// It only ever terminates a program that <see cref="BrowserBlocklist"/> positively identifies as a blocked
/// browser (by signed product name, then by executable name) or, when the administrator chose to block it,
/// as the Microsoft Store app. Google Chrome, Windows system processes and
/// everything else are never touched. It does not hide itself, inject into processes, or fight security
/// software — it is a visible, named service that closes disallowed browsers, nothing more.
/// </summary>
internal sealed class BrowserWatchdog(ILogger<BrowserWatchdog> log) : BackgroundService
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromMilliseconds(1500);
    private readonly HashSet<long> _checked = [];
    private string _systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (SecretStore.Get(SecretStore.Token) is not null)
                {
                    // Read the choices (installer consent + dashboard) once per scan; they are registry values.
                    var browsers = Choices.ChromeOnly;
                    var store = Choices.BlockStore;
                    if (browsers || store)
                    {
                        ScanAndTerminate(p => Decide(p, browsers, store), log);
                    }
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                log.LogDebug(e, "Browser watchdog scan error");
            }
            try
            {
                await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// The watchdog's decision. It runs only when the PC is enrolled, and only for what the administrator
    /// consented to in the installer and the dashboard has on: other browsers and/or the Microsoft Store.
    /// </summary>
    public static bool Decide(ProcessSnapshot p, bool blockBrowsers, bool blockStore)
    {
        ArgumentNullException.ThrowIfNull(p);
        return (blockBrowsers && BrowserBlocklist.IsBlockedBrowser(p.ProductName, p.CompanyName, p.FileName))
            || (blockStore && BrowserBlocklist.IsMicrosoftStore(p.Path));
    }

    /// <summary>
    /// Enumerates processes and terminates those the predicate marks as blocked. Separated from the loop and
    /// parameterised by the predicate so the terminate mechanism is unit-tested on Windows without needing a
    /// real browser's metadata.
    /// </summary>
    public int ScanAndTerminate(Func<ProcessSnapshot, bool> isBlocked, ILogger log)
    {
        ArgumentNullException.ThrowIfNull(isBlocked);
        var alive = new HashSet<long>();
        var killed = 0;
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var key = ProcessKey(proc);
                alive.Add(key);
                if (_checked.Contains(key))
                {
                    continue;
                }
                _checked.Add(key);
                var snapshot = Describe(proc);
                if (snapshot is null)
                {
                    continue;
                }
                // Never touch anything that lives under the Windows directory (no real browser does).
                if (snapshot.Path is { Length: > 0 } path && path.StartsWith(_systemRoot, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (isBlocked(snapshot))
                {
                    Terminate(proc, snapshot);
                    killed++;
                }
            }
            catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Process exited while we inspected it, or access was denied: ignore and move on.
            }
            finally
            {
                proc.Dispose();
            }
        }
        _checked.IntersectWith(alive);     // forget processes that have exited
        return killed;
    }

    private void Terminate(Process proc, ProcessSnapshot snapshot)
    {
        try
        {
            proc.Kill(entireProcessTree: true);
            log.LogInformation("Blocked program closed: {Name} ({Product})", snapshot.FileName,
                snapshot.ProductName ?? "?");
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            log.LogWarning("Could not close blocked program {Name}: {Error}", snapshot.FileName, e.Message);
        }
    }

    private static long ProcessKey(Process proc)
    {
        // PID plus start time, so a reused PID is treated as a new process.
        long start;
        try
        {
            start = proc.StartTime.ToUniversalTime().Ticks;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            start = 0;
        }
        return ((long)proc.Id << 20) ^ start;
    }

    private static ProcessSnapshot? Describe(Process proc)
    {
        var path = ImagePath(proc);
        if (path is null)
        {
            return null;
        }
        var fileName = Path.GetFileName(path);
        string? product = null;
        string? company = null;
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            product = info.ProductName;
            company = info.CompanyName;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
        return new ProcessSnapshot(proc.Id, path, product, company, fileName);
    }

    private static unsafe string? ImagePath(Process proc)
    {
        var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)proc.Id);
        if (h == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;
            fixed (char* b = buffer)
            {
                return Win32.QueryFullProcessImageName(h, 0, b, ref size) ? new string(buffer, 0, (int)size) : null;
            }
        }
        finally
        {
            Win32.CloseHandle(h);
        }
    }
}
