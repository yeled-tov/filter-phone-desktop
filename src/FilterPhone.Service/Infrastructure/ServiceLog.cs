using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using FilterPhone.Core.Util;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// File logger for the service. Every line is passed through <see cref="Redactor"/>; files live in the
/// SYSTEM/Administrators-only log folder and rotate daily with a size cap (7 days kept).
/// A ring buffer of the latest lines feeds the user's (redacted) diagnostic export.
/// </summary>
internal sealed class ServiceLog : ILoggerProvider
{
    private const long MaxBytesPerFile = 5 * 1024 * 1024;
    private const int KeepDays = 7;
    private const int RingSize = 200;

    private readonly object _gate = new();
    private readonly ConcurrentQueue<string> _ring = new();
    private readonly string _dir;

    public ServiceLog(string dir)
    {
        _dir = dir;
        Prune();
    }

    public static ServiceLog? Instance { get; set; }

    public IReadOnlyList<string> Recent() => _ring.ToArray();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Write(LogLevel level, string category, string message, Exception? ex)
    {
        var shortCategory = category[(category.LastIndexOf('.') + 1)..];
        var error = ex is null ? string.Empty : $" [{ex.GetType().Name}: {ex.Message}]";
        var line = Redactor.Redact(string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:yyyy-MM-ddTHH:mm:ssZ} {Short(level)} {shortCategory}: {message}{error}"));
        _ring.Enqueue(line);
        while (_ring.Count > RingSize && _ring.TryDequeue(out _))
        {
        }
        lock (_gate)
        {
            try
            {
                var file = Path.Combine(_dir, $"service-{DateTime.UtcNow:yyyyMMdd}.log");
                if (File.Exists(file) && new FileInfo(file).Length > MaxBytesPerFile)
                {
                    return;
                }
                File.AppendAllText(file, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (IOException)
            {
                // Logging must never take the protection service down.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void Prune()
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(_dir, "service-*.log"))
            {
                if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-KeepDays))
                {
                    File.Delete(f);
                }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string Short(LogLevel l) => l switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "---",
    };

    public void Dispose()
    {
    }

    private sealed class Logger(ServiceLog owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                owner.Write(logLevel, category, formatter(state, exception), exception);
            }
        }
    }
}
