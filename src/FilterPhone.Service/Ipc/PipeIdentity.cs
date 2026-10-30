using System.IO.Pipes;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Native;

namespace FilterPhone.Service.Ipc;

/// <summary>Checks that the pipe is served by this installed FilterPhone.Service.exe, not by a program squatting the name.</summary>
internal static class PipeIdentity
{
    public static unsafe bool IsOurService(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!Win32.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
        {
            return false;
        }
        var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
        {
            return false;
        }
        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;
            fixed (char* b = buffer)
            {
                if (!Win32.QueryFullProcessImageName(h, 0, b, ref size))
                {
                    return false;
                }
            }
            return string.Equals(Path.GetFullPath(new string(buffer, 0, (int)size)), Path.GetFullPath(Paths.ServiceExecutable),
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Win32.CloseHandle(h);
        }
    }
}
