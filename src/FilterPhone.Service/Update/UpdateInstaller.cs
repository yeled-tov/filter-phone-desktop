using System.Diagnostics;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Update;

/// <summary>Launches the verified installer for a silent, in-place upgrade, detached from this service.</summary>
internal static class UpdateInstaller
{
    // Inno Setup silent-upgrade switches: no UI, no prompts, no reboot, do not close/restart other apps.
    private const string Args = "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /NOCANCEL /NORESTARTAPPLICATIONS";

    /// <summary>
    /// Starts the installer through "cmd /c start" so it is a detached process, not a child of this service:
    /// when the installer stops the service to replace its files, the installer itself keeps running and then
    /// starts the upgraded service again.
    /// </summary>
    public static void RunSilently(string installerPath, ILogger log)
    {
        ArgumentNullException.ThrowIfNull(log);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Path.Combine(Paths.System32, "cmd.exe"))
            {
                Arguments = $"/c start \"\" \"{installerPath}\" {Args}",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            log.LogWarning(e, "Could not start the update installer");
        }
    }
}
