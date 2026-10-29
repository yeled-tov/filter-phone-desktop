using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using FilterPhone.Core.Api;
using FilterPhone.Core.Ipc;
using FilterPhone.Service.Engine;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Ipc;

/// <summary>
/// Local IPC for the unprivileged UI. The pipe ACL admits only SYSTEM, Administrators and interactively
/// signed-in users (network logons are denied). The command set cannot weaken protection: status,
/// first-time enrolment, verification, reconnect and a redacted diagnostic report. Every request is parsed
/// strictly, size-limited and rate-limited; file paths are never accepted from the client.
/// </summary>
internal sealed partial class PipeServer(ILogger<PipeServer> log, ProtectionEngine engine) : BackgroundService
{
    private const int MaxInstances = 4;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly RateLimiter _enrollLimit = new(5, TimeSpan.FromMinutes(10));
    private readonly RateLimiter _verifyLimit = new(4, TimeSpan.FromMinutes(1));
    private readonly RateLimiter _reconnectLimit = new(2, TimeSpan.FromMinutes(1));
    private readonly RateLimiter _removalLimit = new(5, TimeSpan.FromMinutes(10));

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var first = true;
        var active = new List<Task>();
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(IpcProtocol.PipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
                    4096, 4096, CreateSecurity());
                first = false;
            }
            catch (IOException e)
            {
                // All instances busy (or, on the first instance, someone else owns the name): wait and retry.
                log.LogWarning("Pipe instance unavailable: {Message}", e.Message);
                await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                continue;
            }
            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }
            active.RemoveAll(t => t.IsCompleted);
            active.Add(HandleAsync(pipe, ct));
        }
        await Task.WhenAll(active).ConfigureAwait(false);
    }

    internal static PipeSecurity CreateSecurity()
    {
        var sec = new PipeSecurity();
        sec.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return sec;
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe.ConfigureAwait(false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(120));
        try
        {
            var frame = await IpcProtocol.ReadFrameAsync(pipe, IpcProtocol.MaxRequestBytes, timeout.Token).ConfigureAwait(false);
            IpcProtocol.Response response;
            try
            {
                var request = IpcProtocol.ParseRequest(frame);
                response = await DispatchAsync(request, timeout.Token).ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                response = new IpcProtocol.Response("0", false, IpcProtocol.Errors.BadRequest, null, null);
            }
            await IpcProtocol.WriteFrameAsync(pipe, IpcProtocol.SerializeResponse(response), IpcProtocol.MaxResponseBytes, timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or InvalidDataException or EndOfStreamException)
        {
            log.LogDebug("IPC connection ended: {Type}", e.GetType().Name);
        }
        catch (Exception e)
        {
            log.LogError(e, "IPC request failed");
        }
    }

    private async Task<IpcProtocol.Response> DispatchAsync(IpcProtocol.Request req, CancellationToken ct)
    {
        switch (req.Command)
        {
            case IpcProtocol.Commands.Status:
                IpcProtocol.RejectUnknownArgs(req.Args);
                return Ok(req, Snapshot(engine.Snapshot));

            case IpcProtocol.Commands.Enroll:
                {
                    IpcProtocol.RejectUnknownArgs(req.Args, "code", "deviceName");
                    var code = IpcProtocol.OptionalString(req.Args, "code", 80, CodePattern())?.Trim()
                        ?? throw new InvalidDataException("code is required");
                    var name = IpcProtocol.OptionalString(req.Args, "deviceName", 60, IpcProtocol.DeviceNamePattern())?.Trim() ?? string.Empty;
                    if (!FilterPhoneApiClient.IsPlausibleCode(code))
                    {
                        return Error(req, IpcProtocol.Errors.InvalidCode, null);
                    }
                    if (!_enrollLimit.Allow())
                    {
                        return Error(req, IpcProtocol.Errors.RateLimited, null);
                    }
                    try
                    {
                        await engine.EnrollAsync(code, name, ct).ConfigureAwait(false);
                        return Ok(req, Snapshot(engine.Snapshot));
                    }
                    catch (EnrollmentException e)
                    {
                        log.LogWarning("Enrolment refused: {Code}", e.Code);
                        return Error(req, e.Code, e.ServerMessage);
                    }
                }

            case IpcProtocol.Commands.Verify:
                IpcProtocol.RejectUnknownArgs(req.Args);
                if (!_verifyLimit.Allow())
                {
                    return Error(req, IpcProtocol.Errors.RateLimited, null);
                }
                return Ok(req, Snapshot(await engine.VerifyNowAsync(ct).ConfigureAwait(false)));

            case IpcProtocol.Commands.Reconnect:
                IpcProtocol.RejectUnknownArgs(req.Args);
                if (!_reconnectLimit.Allow())
                {
                    return Error(req, IpcProtocol.Errors.RateLimited, null);
                }
                engine.ReconnectNow();
                return Ok(req, Snapshot(engine.Snapshot));

            case IpcProtocol.Commands.Diagnostics:
                IpcProtocol.RejectUnknownArgs(req.Args);
                return Ok(req, new JsonObject { ["report"] = engine.Diagnostics() });

            case IpcProtocol.Commands.AuthorizeRemoval:
                {
                    IpcProtocol.RejectUnknownArgs(req.Args, "code");
                    var code = IpcProtocol.OptionalString(req.Args, "code", 40, RemovalCodePattern()) ?? string.Empty;
                    if (!_removalLimit.Allow())
                    {
                        return Error(req, IpcProtocol.Errors.RateLimited, null);
                    }
                    return await engine.AuthorizeRemovalAsync(code, ct).ConfigureAwait(false) switch
                    {
                        RemovalAuthorization.Authorized => Ok(req, new JsonObject { ["authorized"] = true, ["required"] = true }),
                        RemovalAuthorization.NotRequired => Ok(req, new JsonObject { ["authorized"] = true, ["required"] = false }),
                        _ => Error(req, IpcProtocol.Errors.InvalidCode, null),
                    };
                }

            default:
                return Error(req, IpcProtocol.Errors.UnknownCommand, null);
        }
    }

    private static JsonNode? Snapshot(Core.Status.ProtectionSnapshot s) => JsonSerializer.SerializeToNode(s, JsonOptions);

    private static IpcProtocol.Response Ok(IpcProtocol.Request r, JsonNode? data) => new(r.Id, true, null, null, data);

    private static IpcProtocol.Response Error(IpcProtocol.Request r, string code, string? message) => new(r.Id, false, code, message, null);

    [GeneratedRegex(@"^\s*[A-Za-z0-9_-]{6,80}\s*$")]
    private static partial Regex CodePattern();

    [GeneratedRegex(@"^[A-Za-z0-9 -]{0,40}$")]
    private static partial Regex RemovalCodePattern();

    private sealed class RateLimiter(int limit, TimeSpan window)
    {
        private readonly Queue<DateTimeOffset> _hits = new();

        public bool Allow()
        {
            lock (_hits)
            {
                var now = DateTimeOffset.UtcNow;
                while (_hits.Count > 0 && now - _hits.Peek() > window)
                {
                    _hits.Dequeue();
                }
                if (_hits.Count >= limit)
                {
                    return false;
                }
                _hits.Enqueue(now);
                return true;
            }
        }
    }
}
