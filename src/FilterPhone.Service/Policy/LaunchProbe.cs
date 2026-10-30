using System.Runtime.InteropServices;
using FilterPhone.Service.Native;

namespace FilterPhone.Service.Policy;

internal enum LaunchResult
{
    Allowed,
    BlockedByPolicy,
    NotFound,
    NoUserSession,
    Error,
}

/// <summary>
/// Proves application-control enforcement for the signed-in user without running anything: the program is
/// created suspended with the user's own token (CreateProcessAsUser) and, if Windows allowed it, terminated
/// before its first instruction runs. Windows application control refuses the creation itself with
/// ERROR_ACCESS_DISABLED_BY_POLICY, so the result reflects real enforcement, not a policy simulation.
/// </summary>
internal static unsafe class LaunchProbe
{
    public static LaunchResult Try(string exePath)
    {
        if (!File.Exists(exePath))
        {
            return LaunchResult.NotFound;
        }
        var session = Win32.WTSGetActiveConsoleSessionId();
        if (session == Win32.INVALID_SESSION || !Win32.WTSQueryUserToken(session, out var token))
        {
            return LaunchResult.NoUserSession;
        }
        try
        {
            var si = new STARTUPINFOW { cb = (uint)sizeof(STARTUPINFOW) };
            PROCESS_INFORMATION pi = default;
            var cmd = ("\"" + exePath + "\"\0").ToCharArray();
            fixed (char* pCmd = cmd)
            {
                var ok = Win32.CreateProcessAsUser(token, exePath, pCmd, IntPtr.Zero, IntPtr.Zero, false,
                    Win32.CREATE_SUSPENDED | Win32.CREATE_NO_WINDOW, IntPtr.Zero, Infrastructure.Paths.System32, &si, &pi);
                if (!ok)
                {
                    var err = Marshal.GetLastPInvokeError();
                    return err == Win32.ERROR_ACCESS_DISABLED_BY_POLICY ? LaunchResult.BlockedByPolicy
                        : err == Win32.ERROR_FILE_NOT_FOUND ? LaunchResult.NotFound
                        : LaunchResult.Error;
                }
            }
            Win32.TerminateProcess(pi.hProcess, 1);
            Win32.CloseHandle(pi.hThread);
            Win32.CloseHandle(pi.hProcess);
            return LaunchResult.Allowed;
        }
        finally
        {
            Win32.CloseHandle(token);
        }
    }
}
