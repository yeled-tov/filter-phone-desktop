using System.Diagnostics;
using FilterPhone.Service.Policy;
using Microsoft.Extensions.Logging.Abstractions;

namespace FilterPhone.Windows.Tests;

/// <summary>
/// Exercises the real process enumerate-and-terminate mechanism of the watchdog, using a harmless copy of
/// cmd.exe placed outside the Windows directory as a stand-in for a browser. The decision logic itself is
/// covered cross-platform by BrowserBlocklistTests.
/// </summary>
public sealed class BrowserWatchdogTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("fp-wd-").FullName;

    public void Dispose()
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(_dir, recursive: true);
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // The fake process may not have released its image file yet; wait briefly and retry.
                Thread.Sleep(200);
            }
        }
    }

    private static void KillAndWait(Process p)
    {
        try
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
            }
            p.WaitForExit(5000);
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
    }

    private Process StartFakeBrowser(string name)
    {
        var exe = Path.Combine(_dir, name);
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"), exe, overwrite: true);
        var p = Process.Start(new ProcessStartInfo(exe)
        {
            Arguments = "/c ping 127.0.0.1 -n 60 >nul",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
        })!;
        Assert.False(p.WaitForExit(500), "the fake browser should stay running");
        return p;
    }

    private static bool WaitForExit(Process p) => p.WaitForExit(TimeSpan.FromSeconds(10));

    [Fact]
    public void Terminates_a_process_the_predicate_marks_as_a_blocked_browser()
    {
        var watchdog = new BrowserWatchdog(NullLogger<BrowserWatchdog>.Instance);
        using var fake = StartFakeBrowser("fakebrowser.exe");
        var killed = watchdog.ScanAndTerminate(s => string.Equals(s.FileName, "fakebrowser.exe", StringComparison.OrdinalIgnoreCase), NullLogger.Instance);
        Assert.True(killed >= 1);
        Assert.True(WaitForExit(fake), "the blocked process should have been terminated");
        KillAndWait(fake);
    }

    [Fact]
    public void Leaves_processes_the_predicate_allows_running()
    {
        var watchdog = new BrowserWatchdog(NullLogger<BrowserWatchdog>.Instance);
        using var fake = StartFakeBrowser("allowed.exe");
        try
        {
            var killed = watchdog.ScanAndTerminate(_ => false, NullLogger.Instance);
            Assert.Equal(0, killed);
            Assert.False(fake.WaitForExit(500), "a process the predicate allows must keep running");
        }
        finally
        {
            KillAndWait(fake);
        }
    }

    [Fact]
    public void Never_terminates_processes_under_the_windows_directory()
    {
        // A predicate that would match cmd.exe must not kill the real System32 cmd processes (system-dir skip).
        var watchdog = new BrowserWatchdog(NullLogger<BrowserWatchdog>.Instance);
        using var systemCmd = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"))
        {
            Arguments = "/c ping 127.0.0.1 -n 60 >nul",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
        })!;
        try
        {
            watchdog.ScanAndTerminate(s => string.Equals(s.FileName, "cmd.exe", StringComparison.OrdinalIgnoreCase), NullLogger.Instance);
            Assert.False(systemCmd.WaitForExit(500), "processes under %WINDIR% must never be terminated");
        }
        finally
        {
            KillAndWait(systemCmd);
        }
    }
}
