namespace FilterPhone.Core.Util;

/// <summary>
/// Bounded exponential back-off with jitter (5 s → 15 min, like the Android TunnelManager).
/// Never returns zero, so a failing operation can never spin in a tight loop.
/// </summary>
public sealed class Backoff
{
    private static readonly TimeSpan[] DefaultSteps =
    [
        TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15),
    ];

    private readonly TimeSpan[] _steps;
    private readonly Func<double> _random;
    private int _failures;

    public Backoff(TimeSpan[]? steps = null, Func<double>? random = null)
    {
        _steps = steps is { Length: > 0 } ? steps : DefaultSteps;
        if (_steps.Any(s => s <= TimeSpan.Zero))
        {
            throw new ArgumentException("Back-off steps must be positive.", nameof(steps));
        }
        _random = random ?? Random.Shared.NextDouble;
    }

    public int Failures => _failures;

    public DateTimeOffset NotBefore { get; private set; } = DateTimeOffset.MinValue;

    public bool CanAttempt(DateTimeOffset now) => now >= NotBefore;

    /// <summary>Records a failure and returns how long to wait before the next attempt (±20 % jitter).</summary>
    public TimeSpan Failed(DateTimeOffset now)
    {
        var step = _steps[Math.Min(_failures, _steps.Length - 1)];
        _failures = Math.Min(_failures + 1, 1_000);
        var jitter = 0.8 + (_random() * 0.4);
        var delay = TimeSpan.FromMilliseconds(Math.Max(1_000, step.TotalMilliseconds * jitter));
        NotBefore = now + delay;
        return delay;
    }

    public void Succeeded()
    {
        _failures = 0;
        NotBefore = DateTimeOffset.MinValue;
    }
}
