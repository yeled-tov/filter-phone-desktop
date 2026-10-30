using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        var path = ProcessPath(pid);
        if (path is null || !string.Equals(Path.GetFullPath(path), Path.GetFullPath(ExpectedServicePath), StringComparison.OrdinalIgnoreCase))
        {
            throw new ServiceUnavailableException("server_not_trusted");
        }
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

    internal static Win32Exception LastError() => new(Marshal.GetLastPInvokeError());
}
