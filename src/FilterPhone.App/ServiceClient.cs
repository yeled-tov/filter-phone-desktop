using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using FilterPhone.Core;
using FilterPhone.Core.Ipc;
using FilterPhone.Core.Status;

namespace FilterPhone.App;

public sealed class ServiceUnavailableException(string message) : Exception(message);

public sealed record ServiceReply(bool Ok, string? Error, string? Message, JsonNode? Data);

/// <summary>
/// Talks to the protection service. Before sending anything it checks that the pipe is served by the
/// installed FilterPhone.Service.exe (defends against another program squatting the pipe name).
/// </summary>
public static partial class ServiceClient
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public static string ExpectedServicePath => Path.Combine(AppContext.BaseDirectory, "FilterPhone.Service.exe");

    public static async Task<ServiceReply> SendAsync(string command, JsonObject? args, TimeSpan timeout, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        await using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(3000, cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
        {
            throw new ServiceUnavailableException("pipe_unavailable");
        }
        VerifyServer(pipe);
        var request = new IpcProtocol.Request(Guid.NewGuid().ToString("N"), command, args ?? new JsonObject());
        await IpcProtocol.WriteFrameAsync(pipe, IpcProtocol.SerializeRequest(request), IpcProtocol.MaxRequestBytes, cts.Token).ConfigureAwait(false);
        var bytes = await IpcProtocol.ReadFrameAsync(pipe, IpcProtocol.MaxResponseBytes, cts.Token).ConfigureAwait(false);
        var r = IpcProtocol.ParseResponse(bytes);
        return new ServiceReply(r.Ok, r.Error, r.Message, r.Data);
    }

    public static ProtectionSnapshot? ParseSnapshot(JsonNode? data) =>
        data is null ? null : data.Deserialize<ProtectionSnapshot>(Options);

    private static void VerifyServer(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
        {
            throw new ServiceUnavailableException("server_unknown");
        }
        // The UI runs as a standard user, who may not open a process running as SYSTEM, so the server's image path is
        // normally unreadable here. The Service Control Manager tells any interactive user which process our service
        // runs in; a program squatting the pipe name is a different process.
        if (!IsTrustedServer(pid, RunningServicePid(ProductConfig.ServiceName), ProcessPath(pid), ExpectedServicePath))
        {
            throw new ServiceUnavailableException("server_not_trusted");
        }
    }

    /// <summary>
    /// The pipe is ours when it is served by the process the SCM reports for the FilterPhone service, or (when the
    /// path is readable, e.g. elevated) by the installed FilterPhone.Service.exe itself.
    /// </summary>
    internal static bool IsTrustedServer(uint pipeServerPid, uint? servicePid, string? serverPath, string expectedPath) =>
        (servicePid is { } sp && sp != 0 && sp == pipeServerPid)
        || (serverPath is not null
            && string.Equals(Path.GetFullPath(serverPath), Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase));

    /// <summary>The process id of the service while it is running, or null (not installed, stopped, or no access).</summary>
    internal static unsafe uint? RunningServicePid(string serviceName)
    {
        const uint SC_MANAGER_CONNECT = 0x0001;
        const uint SERVICE_QUERY_STATUS = 0x0004;
        const int SC_STATUS_PROCESS_INFO = 0;
        const uint SERVICE_RUNNING = 4;
        var scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            var service = OpenService(scm, serviceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
            {
                return null;
            }
            try
            {
                ServiceStatusProcess status;
                if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, &status, (uint)sizeof(ServiceStatusProcess), out _))
                {
                    return null;
                }
                return status.CurrentState == SERVICE_RUNNING && status.ProcessId != 0 ? status.ProcessId : null;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    private static unsafe string? ProcessPath(uint pid)
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
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
                return QueryFullProcessImageName(h, 0, b, ref size) ? new string(buffer, 0, (int)size) : null;
            }
        }
        finally
        {
            CloseHandle(h);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(IntPtr process, uint flags, char* name, ref uint size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr h);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenService(IntPtr scManager, string serviceName, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryServiceStatusEx(IntPtr service, int infoLevel, ServiceStatusProcess* buffer, uint bufferSize, out uint bytesNeeded);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);

    internal static Win32Exception LastError() => new(Marshal.GetLastPInvokeError());
}
