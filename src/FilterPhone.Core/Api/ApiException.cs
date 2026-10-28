using System.Net;

namespace FilterPhone.Core.Api;

public enum ApiErrorKind
{
    Network,
    Timeout,
    Tls,
    BadRequest,
    Unauthorized,
    Forbidden,
    Conflict,
    TooLarge,
    RateLimited,
    ServerError,
    InvalidResponse,
}

/// <summary>
/// A failed API call. <see cref="ServerMessage"/> is the server's own (Hebrew) explanation when it sent one;
/// it is shown to the user as-is because the server already phrases it for end users.
/// </summary>
public sealed class ApiException : Exception
{
    public ApiException(ApiErrorKind kind, int status, string? serverMessage, Exception? inner = null)
        : base($"FilterPhone API error {kind} ({status})", inner)
    {
        Kind = kind;
        Status = status;
        ServerMessage = serverMessage;
    }

    public ApiErrorKind Kind { get; }

    /// <summary>HTTP status, or 0 when no response arrived.</summary>
    public int Status { get; }

    public string? ServerMessage { get; }

    /// <summary>True when retrying later can help (outage, timeout, rate limit, 5xx).</summary>
    public bool IsTransient => Kind is ApiErrorKind.Network or ApiErrorKind.Timeout or ApiErrorKind.RateLimited
        or ApiErrorKind.ServerError;

    internal static ApiErrorKind FromStatus(HttpStatusCode code) => (int)code switch
    {
        400 => ApiErrorKind.BadRequest,
        401 => ApiErrorKind.Unauthorized,
        403 => ApiErrorKind.Forbidden,
        409 => ApiErrorKind.Conflict,
        413 => ApiErrorKind.TooLarge,
        429 => ApiErrorKind.RateLimited,
        >= 500 => ApiErrorKind.ServerError,
        _ => ApiErrorKind.InvalidResponse,
    };
}
