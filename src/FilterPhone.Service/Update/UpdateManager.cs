using System.Net.Http;
using FilterPhone.Core;
using FilterPhone.Core.Update;
using FilterPhone.Service.Infrastructure;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Update;

/// <summary>
/// Keeps FilterPhone up to date by itself: periodically it reads the HTTPS update feed, and when a newer
/// version is offered it downloads the installer (through the filtered tunnel, like all other traffic),
/// checks its SHA-256, and — only if the installer carries a valid Authenticode signature from the configured
/// publisher — runs it silently as the local service, which upgrades FilterPhone in place and restarts it. No
/// window appears and the signed-in user is not asked anything.
///
/// Safety: an installer is never run automatically unless it both matches the feed's SHA-256 and is signed by
/// the expected publisher. On an unsigned build (no publisher configured) an available update is reported to
/// the UI but never installed on its own — downloading an unverified program and running it as SYSTEM would be
/// a remote-code-execution hole. The removal-code gate does not apply here: an in-place upgrade is not an
/// uninstall and keeps the enrolment, consent and data.
/// </summary>
internal sealed class UpdateManager(ILogger<UpdateManager> log, UpdateStatus status) : BackgroundService
{
    private static readonly TimeSpan FirstCheck = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan Every = TimeSpan.FromHours(6);
    private static readonly TimeSpan RetryAfterError = TimeSpan.FromMinutes(30);

    private readonly SemaphoreSlim _checkNow = new(0, 1);
    private string? _installedVersion;    // the version we already launched the installer for (avoid re-running)

    /// <summary>Asks for an immediate check (from the UI's "check for updates" button).</summary>
    public void CheckNow()
    {
        try
        {
            _checkNow.Release();
        }
        catch (SemaphoreFullException)
        {
            // A check is already queued.
        }
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (ProductConfig.UpdatePublisher.Length == 0)
        {
            log.LogInformation("Automatic install is off (no code-signing publisher configured); updates will be reported only");
        }
        var next = DateTimeOffset.UtcNow + FirstCheck;
        while (!ct.IsCancellationRequested)
        {
            var wait = next - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero && !await WaitAsync(wait, ct).ConfigureAwait(false) && DateTimeOffset.UtcNow < next)
            {
                continue;
            }
            if (ct.IsCancellationRequested)
            {
                break;
            }
            var ok = await CheckAndMaybeInstallAsync(ct).ConfigureAwait(false);
            next = DateTimeOffset.UtcNow + (ok ? Every : RetryAfterError);
        }
    }

    /// <summary>Returns false on an error (so the caller retries sooner).</summary>
    private async Task<bool> CheckAndMaybeInstallAsync(CancellationToken ct)
    {
        status.Set(UpdateState.Checking);
        try
        {
            var manifest = await FetchManifestAsync(ct).ConfigureAwait(false);
            if (manifest is null || !manifest.IsNewerThan(ProductConfig.Version))
            {
                status.Set(UpdateState.UpToDate);
                return true;
            }
            var version = manifest.Version.ToString();
            if (ProductConfig.UpdatePublisher.Length == 0)
            {
                status.Set(UpdateState.Available, version);   // unsigned build: tell the user, do not install
                log.LogInformation("Update {Version} is available but automatic install is off (unsigned build)", version);
                return true;
            }
            if (_installedVersion == version)
            {
                status.Set(UpdateState.Installing, version);  // already launched; a restart will complete it
                return true;
            }
            status.Set(UpdateState.Downloading, version);
            var installer = await DownloadAndVerifyAsync(manifest, ct).ConfigureAwait(false);
            if (installer is null)
            {
                status.Set(UpdateState.Error, version);
                return false;
            }
            status.Set(UpdateState.Installing, version);
            UpdateInstaller.RunSilently(installer, log);
            _installedVersion = version;
            log.LogInformation("Update {Version} verified and the silent in-place upgrade was started", version);
            return true;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException or UriFormatException
                                      or InvalidOperationException && !ct.IsCancellationRequested)
        {
            log.LogInformation("Update check failed ({Type}); will retry", e.GetType().Name);
            status.Set(UpdateState.Error);
            return false;
        }
    }

    private static async Task<UpdateManifest?> FetchManifestAsync(CancellationToken ct)
    {
        if (!Uri.TryCreate(ProductConfig.UpdateManifestUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }
        using var http = NewClient(TimeSpan.FromSeconds(30), 64 * 1024);
        return UpdateManifest.Parse(await http.GetStringAsync(uri, ct).ConfigureAwait(false));
    }

    private async Task<string?> DownloadAndVerifyAsync(UpdateManifest manifest, CancellationToken ct)
    {
        SecureDirectory.EnsureAll();
        var file = Path.Combine(Paths.Updates, "FilterPhone-Desktop-Setup.exe");
        Delete(file);
        using (var http = NewClient(TimeSpan.FromMinutes(15), 0))
        await using (var stream = await http.GetStreamAsync(manifest.Url, ct).ConfigureAwait(false))
        await using (var fs = File.Create(file))
        {
            await stream.CopyToAsync(fs, ct).ConfigureAwait(false);
        }
        var sha = await Sha256Async(file, ct).ConfigureAwait(false);
        if (!string.Equals(sha, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            log.LogWarning("Downloaded update failed the SHA-256 check");
            Delete(file);
            return null;
        }
        if (!SignatureVerifier.IsTrusted(file, ProductConfig.UpdatePublisher, out var reason))
        {
            log.LogWarning("Downloaded update is not signed by the expected publisher ({Reason})", reason);
            Delete(file);
            return null;
        }
        return file;
    }

    private static HttpClient NewClient(TimeSpan timeout, int maxBuffer)
    {
        // A plain client: with the tunnel up its traffic is routed and filtered through WireGuard like Chrome's.
        var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 })
        {
            Timeout = timeout,
        };
        if (maxBuffer > 0)
        {
            client.MaxResponseContentBufferSize = maxBuffer;
        }
        client.DefaultRequestHeaders.UserAgent.ParseAdd("FilterPhone-Desktop/" + ProductConfig.Version);
        return client;
    }

    private static async Task<string> Sha256Async(string file, CancellationToken ct)
    {
        await using var fs = File.OpenRead(file);
        return Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(fs, ct).ConfigureAwait(false));
    }

    private static void Delete(string file)
    {
        try
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }
        catch (IOException)
        {
        }
    }

    private async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            return await _checkNow.WaitAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
