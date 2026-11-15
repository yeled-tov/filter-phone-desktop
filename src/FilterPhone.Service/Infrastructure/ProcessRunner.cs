using System.Diagnostics;
using System.Text;

namespace FilterPhone.Service.Infrastructure;

internal sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);

/// <summary>
/// Runs a fixed executable with an explicit argument list. Never uses a shell, never builds a command line
/// from untrusted text, and never passes secrets as arguments (secrets travel in protected files only).
/// </summary>
internal static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(string exe, IEnumerable<string> args, TimeSpan timeout, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(exe))
        {
            throw new ArgumentException("Executable path must be absolute.", nameof(exe));
        }
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Paths.System32,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }
        using var p = new Process { StartInfo = psi };
        p.Start();
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }
            throw new TimeoutException($"{Path.GetFileName(exe)} did not finish in {timeout.TotalSeconds:0}s.");
        }
        return new ProcessResult(p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    public static string PowerShell => Path.Combine(Paths.System32, "WindowsPowerShell", "v1.0", "powershell.exe");
}
