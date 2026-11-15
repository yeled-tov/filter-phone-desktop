using System.IO.Pipes;
using System.ServiceProcess;
using System.Text.Json.Nodes;
using FilterPhone.Core.Ipc;
using FilterPhone.Service.Infrastructure;

namespace FilterPhone.Service.Ipc;

/// <summary>
/// Used by the uninstaller (elevated):
///   --removal-status            exit 0 = removal may proceed, 10 = a removal code from the dashboard is needed
///   --authorize-removal CODE    asks the running service to check CODE; exit 0 = authorized (confirmed in the
///                               machine state), 2 = wrong or expired code, 4 = too many attempts, 3 = the
///                               protection service is not available
/// </summary>
internal static class RemovalCli
{
    public const int Allowed = 0;
    public const int WrongCode = 2;
    public const int ServiceUnavailable = 3;
    public const int TooManyAttempts = 4;
    public const int CodeNeeded = 10;

    public static int Status() => RemovalGate.Allowed(MachineState.Load(), DateTimeOffset.UtcNow) ? Allowed : CodeNeeded;

    public static async Task<int> AuthorizeAsync(string code)
    {
        if (Status() == Allowed)
        {
            return Allowed;
        }
        EnsureServiceRunning();
        IpcProtocol.Response response;
        try
        {
            await using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await pipe.ConnectAsync(10_000, cts.Token).ConfigureAwait(false);
            if (!PipeIdentity.IsOurService(pipe))
            {
                Console.Error.WriteLine("The pipe is not served by the installed FilterPhone service.");
                return ServiceUnavailable;
            }
            var request = new IpcProtocol.Request(Guid.NewGuid().ToString("N"), IpcProtocol.Commands.AuthorizeRemoval,
                new JsonObject { ["code"] = code });
            await IpcProtocol.WriteFrameAsync(pipe, IpcProtocol.SerializeRequest(request), IpcProtocol.MaxRequestBytes, cts.Token).ConfigureAwait(false);
            response = IpcProtocol.ParseResponse(await IpcProtocol.ReadFrameAsync(pipe, IpcProtocol.MaxResponseBytes, cts.Token).ConfigureAwait(false));
        }
        catch (Exception e) when (e is System.TimeoutException or IOException or OperationCanceledException or UnauthorizedAccessException or InvalidDataException)
        {
            Console.Error.WriteLine("The FilterPhone protection service is not answering.");
            return ServiceUnavailable;
        }
        if (!response.Ok)
        {
            return response.Error == IpcProtocol.Errors.RateLimited ? TooManyAttempts : WrongCode;
        }
        // Trust the machine state written by the service, not only the reply.
        return Status() == Allowed ? Allowed : WrongCode;
    }

    private static void EnsureServiceRunning()
    {
        try
        {
            using var sc = new ServiceController(Paths.ServiceName);
            if (sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
            {
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or System.ServiceProcess.TimeoutException)
        {
            // Reported as "service unavailable" by the connection attempt that follows.
        }
    }
}
