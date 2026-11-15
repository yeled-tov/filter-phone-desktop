using System.IO.Pipes;
using System.Text.Json.Nodes;
using FilterPhone.Core.Ipc;

namespace FilterPhone.Service.Ipc;

/// <summary>
/// Command-line client for the running service (administrators, support and automated end-to-end tests):
///   --status            print the protection snapshot (JSON, no secrets)
///   --verify            run all verification checks now and print the snapshot
///   --enroll [name]     read the activation code from standard input (never from the command line)
///   --diagnostics       print the redacted diagnostic report
/// </summary>
internal static class CliClient
{
    public static async Task<int> RunAsync(string[] args)
    {
        var (command, payload) = args[0] switch
        {
            "--status" => (IpcProtocol.Commands.Status, new JsonObject()),
            "--verify" => (IpcProtocol.Commands.Verify, new JsonObject()),
            "--diagnostics" => (IpcProtocol.Commands.Diagnostics, new JsonObject()),
            "--enroll" => (IpcProtocol.Commands.Enroll, new JsonObject
            {
                ["code"] = (await Console.In.ReadLineAsync().ConfigureAwait(false) ?? string.Empty).Trim(),
                ["deviceName"] = args.Length > 1 ? args[1] : string.Empty,
            }),
            _ => (string.Empty, new JsonObject()),
        };
        if (command.Length == 0)
        {
            return 2;
        }
        await using var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await pipe.ConnectAsync(5000, cts.Token).ConfigureAwait(false);
        if (!PipeIdentity.IsOurService(pipe))
        {
            Console.Error.WriteLine("The pipe is not served by the installed FilterPhone service.");
            return 3;
        }
        var request = new IpcProtocol.Request(Guid.NewGuid().ToString("N"), command, payload);
        await IpcProtocol.WriteFrameAsync(pipe, IpcProtocol.SerializeRequest(request), IpcProtocol.MaxRequestBytes, cts.Token).ConfigureAwait(false);
        var response = IpcProtocol.ParseResponse(await IpcProtocol.ReadFrameAsync(pipe, IpcProtocol.MaxResponseBytes, cts.Token).ConfigureAwait(false));
        if (command == IpcProtocol.Commands.Diagnostics && response.Data?["report"] is JsonNode report)
        {
            Console.WriteLine(report.GetValue<string>());
        }
        else
        {
            Console.WriteLine(new JsonObject
            {
                ["ok"] = response.Ok,
                ["error"] = response.Error,
                ["message"] = response.Message,
                ["data"] = response.Data?.DeepClone(),
            }.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }
        return response.Ok ? 0 : 1;
    }
}
