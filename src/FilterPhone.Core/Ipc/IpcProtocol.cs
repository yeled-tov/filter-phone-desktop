using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FilterPhone.Core.Ipc;

/// <summary>
/// The local protocol between the unprivileged UI and the protection service over a named pipe.
/// Frames are a 4-byte little-endian length followed by UTF-8 JSON. The command set is fixed and small:
/// none of the commands can weaken protection, and every argument is validated by the service. The only
/// command related to removal needs a valid removal code from the dashboard and only authorizes the
/// uninstaller (which itself needs an administrator).
/// </summary>
public static partial class IpcProtocol
{
    public const string PipeName = "FilterPhone.Service.v1";
    public const int Version = 1;
    public const int MaxRequestBytes = 16 * 1024;
    public const int MaxResponseBytes = 1024 * 1024;

    public static class Commands
    {
        public const string Status = "status";
        public const string Enroll = "enroll";
        public const string Verify = "verify";
        public const string Reconnect = "reconnect";
        public const string Diagnostics = "diagnostics";
        /// <summary>Checks a removal code issued in the dashboard; on success the uninstall is authorized for a short time.</summary>
        public const string AuthorizeRemoval = "authorize_removal";

        public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
            { Status, Enroll, Verify, Reconnect, Diagnostics, AuthorizeRemoval };
    }

    public static class Errors
    {
        public const string BadRequest = "bad_request";
        public const string UnknownCommand = "unknown_command";
        public const string AlreadyEnrolled = "already_enrolled";
        public const string RateLimited = "rate_limited";
        public const string InvalidCode = "invalid_code";
        public const string Network = "network";
        public const string Server = "server";
        public const string Internal = "internal";
        public const string Busy = "busy";
    }

    public sealed record Request(string Id, string Command, JsonObject Args);

    public sealed record Response(string Id, bool Ok, string? Error, string? Message, JsonNode? Data);

    public static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, int maxBytes, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.Length > maxBytes)
        {
            throw new InvalidDataException("IPC frame too large.");
        }
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadFrameAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
        {
            throw new InvalidDataException("IPC frame length is invalid.");
        }
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
        return buffer;
    }

    public static byte[] SerializeRequest(Request request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var o = new JsonObject
        {
            ["v"] = Version,
            ["id"] = request.Id,
            ["cmd"] = request.Command,
            ["args"] = request.Args.DeepClone(),
        };
        return JsonSerializer.SerializeToUtf8Bytes(o);
    }

    public static byte[] SerializeResponse(Response response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var o = new JsonObject
        {
            ["v"] = Version,
            ["id"] = response.Id,
            ["ok"] = response.Ok,
            ["error"] = response.Error,
            ["message"] = response.Message,
            ["data"] = response.Data?.DeepClone(),
        };
        return JsonSerializer.SerializeToUtf8Bytes(o);
    }

    /// <summary>Strict parse: unknown top-level fields, wrong types or unknown commands are rejected.</summary>
    public static Request ParseRequest(ReadOnlySpan<byte> utf8)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(utf8, documentOptions: new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException e)
        {
            throw new InvalidDataException("Request is not valid JSON.", e);
        }
        if (node is not JsonObject o)
        {
            throw new InvalidDataException("Request must be an object.");
        }
        foreach (var key in o.Select(p => p.Key))
        {
            if (key is not ("v" or "id" or "cmd" or "args"))
            {
                throw new InvalidDataException("Unexpected field in request.");
            }
        }
        if (o["v"]?.GetValueKind() != JsonValueKind.Number || o["v"]!.GetValue<int>() != Version)
        {
            throw new InvalidDataException("Unsupported protocol version.");
        }
        var id = o["id"]?.GetValueKind() == JsonValueKind.String ? o["id"]!.GetValue<string>() : null;
        if (id is null || !RequestId().IsMatch(id))
        {
            throw new InvalidDataException("Request id is invalid.");
        }
        var cmd = o["cmd"]?.GetValueKind() == JsonValueKind.String ? o["cmd"]!.GetValue<string>() : null;
        if (cmd is null || !Commands.All.Contains(cmd))
        {
            throw new InvalidDataException("Unknown command.");
        }
        var args = o["args"] switch
        {
            null => new JsonObject(),
            JsonObject a => (JsonObject)a.DeepClone(),
            _ => throw new InvalidDataException("Arguments must be an object."),
        };
        return new Request(id, cmd, args);
    }

    public static Response ParseResponse(ReadOnlySpan<byte> utf8)
    {
        var o = JsonNode.Parse(utf8) as JsonObject ?? throw new InvalidDataException("Response must be an object.");
        return new Response(
            o["id"]?.GetValue<string>() ?? string.Empty,
            o["ok"]?.GetValue<bool>() ?? false,
            o["error"]?.GetValueKind() == JsonValueKind.String ? o["error"]!.GetValue<string>() : null,
            o["message"]?.GetValueKind() == JsonValueKind.String ? o["message"]!.GetValue<string>() : null,
            o["data"]?.DeepClone());
    }

    /// <summary>Reads an optional string argument, enforcing a maximum length and an allowed character set.</summary>
    public static string? OptionalString(JsonObject args, string name, int maxLength, Regex? allowed = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        var node = args[name];
        if (node is null)
        {
            return null;
        }
        if (node.GetValueKind() != JsonValueKind.String)
        {
            throw new InvalidDataException($"Argument '{name}' must be a string.");
        }
        var value = node.GetValue<string>();
        if (value.Length > maxLength || (allowed is not null && !allowed.IsMatch(value)))
        {
            throw new InvalidDataException($"Argument '{name}' is invalid.");
        }
        return value;
    }

    public static void RejectUnknownArgs(JsonObject args, params string[] allowed)
    {
        ArgumentNullException.ThrowIfNull(args);
        foreach (var key in args.Select(p => p.Key))
        {
            if (!allowed.Contains(key, StringComparer.Ordinal))
            {
                throw new InvalidDataException("Unexpected argument.");
            }
        }
    }

    [GeneratedRegex("^[A-Za-z0-9-]{1,64}$")]
    private static partial Regex RequestId();

    /// <summary>Device display name: printable text without control or bidi-override characters.</summary>
    [GeneratedRegex(@"^[^\p{Cc}​-‏‪-‮⁦-⁩]{0,60}$")]
    public static partial Regex DeviceNamePattern();
}
