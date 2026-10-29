using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using FilterPhone.Core;
using FilterPhone.Core.Api;
using FilterPhone.Core.Diagnostics;
using FilterPhone.Core.Network;
using FilterPhone.Core.Removal;
using FilterPhone.Core.Status;
using FilterPhone.Core.Trust;
using FilterPhone.Core.Util;
using FilterPhone.Core.Verification;
using FilterPhone.Core.Vpn;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Network;
using FilterPhone.Service.Policy;
using FilterPhone.Service.Trust;
using FilterPhone.Service.Tunnel;
using FilterPhone.Service.Verification;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FilterPhone.Service.Engine;

/// <summary>Outcome of checking a removal code.</summary>
internal enum RemovalAuthorization
{
    Authorized,
    NotRequired,
    WrongCode,
}

public sealed class EnrollmentException(string code, string? serverMessage = null) : Exception(code)
{
    public string Code { get; } = code;
    public string? ServerMessage { get; } = serverMessage;
}

/// <summary>
/// The protection loop. Every 15 seconds (or immediately after a network change, resume or UI request) it
/// makes each layer converge to its required state and records a separate, verified check per layer.
/// Every corrective action goes through a bounded back-off; an exception in one step never stops the loop
/// or the other layers, and no step ever opens the network to "recover".
/// </summary>
internal sealed class ProtectionEngine(
    ILogger<ProtectionEngine> log,
    TunnelController tunnel,
    TrustStore trust,
    ChromeOnlyEnforcer chromeOnly) : BackgroundService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan HandshakeFresh = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan StaleBeforeRestart = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan DataProbeEvery = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan VerifyEvery = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan VpnRefreshEvery = TimeSpan.FromHours(6);
    private static readonly TimeSpan RekeyAfterNoHandshake = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan RekeyMinInterval = TimeSpan.FromHours(6);

    private readonly ConcurrentDictionary<string, LayerCheck> _checks = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly Backoff _tunnelBackoff = new();
    private readonly Backoff _provisionBackoff = new();
    private readonly Backoff _apiBackoff = new();
    private readonly Backoff _dataRestartBackoff = new([TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15)]);
    private readonly Backoff _policyBackoff = new([TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2)]);

    private MachineState _state = new();
    private volatile ProtectionSnapshot _snapshot = new() { Overall = OverallState.NotEnrolled, Checks = new Dictionary<string, LayerCheck>() };
    private DateTimeOffset _nextServerSync = DateTimeOffset.MinValue;
    private DateTimeOffset _nextDataProbe = DateTimeOffset.MinValue;
    private DateTimeOffset _nextVerify = DateTimeOffset.MinValue;
    private DateTimeOffset _nextVpnRefresh = DateTimeOffset.MinValue;
    private DateTimeOffset _nextChromeVerify = DateTimeOffset.MinValue;
    private DateTimeOffset _nextRegistrationCheck = DateTimeOffset.MinValue;
    private (Catalog Catalog, DateTimeOffset At)? _catalog;
    private DateTimeOffset? _staleSince;
    private DateTimeOffset? _noHandshakeSince;
    private DateTimeOffset? _lastHandshake;
    private DateTimeOffset? _lastVerified;
    private DateTimeOffset? _dataFailSince;
    private string? _killSwitchPlanHash;
    private bool _tunnelUpThisRun;
    private bool _apiReachable = true;
    private int _reconnects;
    private int _dataFails;
    private int _dataFailsInRow;
    private bool? _dataOk;
    private string? _dataError;
    private string? _lastTunnelError;

    public ProtectionSnapshot Snapshot => _snapshot;

    public void Wake() => _wake.Release();

    // ------------------------------------------------------------------ loop

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        SecureDirectory.EnsureAll();
        _state = MachineState.Load();
        if (string.IsNullOrEmpty(_state.DeviceUid))
        {
            _state.DeviceUid = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            _state.Save();
        }
        NetworkChange.NetworkAddressChanged += (_, _) => Wake();
        NetworkChange.NetworkAvailabilityChanged += (_, _) => Wake();
        log.LogInformation("FilterPhone service {Version} started on {Edition} build {Build}", ProductConfig.Version,
            WindowsInfo.EditionId, WindowsInfo.Build);

        var lastWall = DateTimeOffset.UtcNow;
        while (!ct.IsCancellationRequested)
        {
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await TickAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                log.LogError(e, "Protection tick failed; continuing");
            }
            finally
            {
                _gate.Release();
                Publish();
            }

            try
            {
                await _wake.WaitAsync(TickInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            var now = DateTimeOffset.UtcNow;
            if (now - lastWall > TickInterval * 4)
            {
                // The machine slept (or the clock jumped): re-check everything now instead of trusting old results.
                log.LogInformation("Resume or clock change detected; re-verifying");
                _staleSince = null;
                _nextDataProbe = _nextServerSync = _nextVerify = DateTimeOffset.MinValue;
            }
            lastWall = now;
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        if (!_state.Enrolled)
        {
            await RegistrationTickAsync(ct).ConfigureAwait(false);
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var token = SecretStore.Get(SecretStore.Token);
        var vpnJson = SecretStore.Get(SecretStore.VpnJson);
        var privateKey = SecretStore.Get(SecretStore.PrivateKey);
        if (token is null || vpnJson is null)
        {
            Set(Layers.Enrollment, CheckState.Failed, "secrets_missing");
            return;
        }
        Set(Layers.Enrollment, CheckState.Ok, _state.ServerStatus == "unauthorized" ? "unauthorized" : "enrolled");
        using var vpnDoc = JsonDocument.Parse(vpnJson);
        var vpn = VpnSettings.Parse(vpnDoc.RootElement);

        // 1. Kill switch first: if it was ever enabled it must be in force before anything else happens.
        EnsureKillSwitch(vpn);

        // 2. Tunnel configuration and service.
        if (privateKey is null || !WireGuardKeys.IsValidKey(privateKey))
        {
            Set(Layers.Tunnel, CheckState.Failed, "key_missing");
            await MaybeRekeyAsync(token, force: true, ct).ConfigureAwait(false);
            return;
        }
        await EnsureTunnelProvisionedAsync(vpn, privateKey, ct).ConfigureAwait(false);
        await CheckTunnelAsync(token, now, ct).ConfigureAwait(false);

        // 3. Filtering CA.
        EnsureCaTrusted();

        // 4. Server view, data path, verification.
        var tunnelOk = _checks.TryGetValue(Layers.Tunnel, out var t) && t.State == CheckState.Ok;
        if (tunnelOk && now >= _nextDataProbe)
        {
            await DataProbeAsync(now, ct).ConfigureAwait(false);
        }
        if (now >= _nextServerSync && _apiBackoff.CanAttempt(now))
        {
            await ServerSyncAsync(token, vpn, tunnelOk, now, ct).ConfigureAwait(false);
        }
        if (now >= _nextVpnRefresh && _apiBackoff.CanAttempt(now))
        {
            await RefreshVpnAsync(token, vpn, privateKey, now, ct).ConfigureAwait(false);
        }
        if (tunnelOk && now >= _nextVerify)
        {
            await VerifyFilteringAsync(now, ct).ConfigureAwait(false);
        }

        // 5. Chrome-only enforcement (after the network protection is in place).
        await EnsureChromeOnlyAsync(now, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ kill switch

    private void EnsureKillSwitch(VpnSettings vpn)
    {
        if (!Consent.NetworkLock)
        {
            Set(Layers.KillSwitch, CheckState.Failed, "consent_missing");
            return;
        }
        if (!_state.NetworkLockEnabled)
        {
            Set(Layers.KillSwitch, CheckState.Pending, "waiting_for_verified_tunnel");
            return;
        }
        try
        {
            var endpoints = ParseAddresses(_state.EndpointAddresses);
            if (vpn.EndpointFallback is { } fb && IPAddress.TryParse(fb.Host, out var fbIp))
            {
                endpoints.Add(fbIp);
            }
            if (vpn.Endpoint.IsIpLiteral)
            {
                endpoints.Add(IPAddress.Parse(vpn.Endpoint.Host));
            }
            var rules = KillSwitchPlan.Build(new KillSwitchInputs(vpn.TunnelIPv4, endpoints.Distinct().ToList(),
                (ushort)vpn.Endpoint.Port, ParseAddresses(_state.ApiAddresses), Paths.ServiceExecutable));
            var hash = string.Join('|', rules.Select(r => $"{r.Name}:{string.Join(',', r.RemoteNetworks)}:{r.LocalAddress}:{r.RemotePort}"));
            if (hash != _killSwitchPlanHash || WfpKillSwitch.InstalledFilterCount() != rules.Count)
            {
                WfpKillSwitch.Apply(rules);
                _killSwitchPlanHash = hash;
                log.LogInformation("Network lock installed ({Count} filters)", rules.Count);
            }
            Set(Layers.KillSwitch, CheckState.Ok, "installed");
        }
        catch (Exception e) when (e is WfpException or ArgumentException or DllNotFoundException)
        {
            log.LogError(e, "Network lock could not be installed");
            Set(Layers.KillSwitch, CheckState.Failed, e is WfpException w ? $"wfp_0x{w.Code:x8}" : "invalid_inputs");
        }
    }

    // ------------------------------------------------------------------ tunnel

    private async Task EnsureTunnelProvisionedAsync(VpnSettings vpn, string privateKey, CancellationToken ct)
    {
        if (!TunnelController.WireGuardInstalled)
        {
            Set(Layers.Tunnel, CheckState.Failed, "wireguard_missing");
            return;
        }
        var endpoint = ResolvedEndpoint(vpn);
        var fingerprint = vpn.Fingerprint() + "|" + endpoint;
        var configCurrent = fingerprint == _state.VpnFingerprint && File.Exists(Paths.TunnelConfig);
        if (configCurrent && TunnelController.IsInstalled())
        {
            return;
        }
        if (!_provisionBackoff.CanAttempt(DateTimeOffset.UtcNow))
        {
            return;
        }
        try
        {
            using var keys = WireGuardKeys.FromPrivateKey(privateKey);
            tunnel.WriteConfig(WireGuardConfigWriter.Render(vpn, keys, endpoint));
            var wasInstalled = TunnelController.IsInstalled();
            await tunnel.InstallAsync(ct).ConfigureAwait(false);
            if (wasInstalled && !configCurrent)
            {
                tunnel.Restart();
                log.LogInformation("Tunnel configuration updated and tunnel restarted");
            }
            _state.VpnFingerprint = fingerprint;
            _state.Save();
            _provisionBackoff.Succeeded();
        }
        catch (Exception e) when (e is TunnelException or IOException or InvalidOperationException or TimeoutException
                                      or System.ComponentModel.Win32Exception)
        {
            var delay = _provisionBackoff.Failed(DateTimeOffset.UtcNow);
            _lastTunnelError = e is TunnelException te ? te.Code : e.GetType().Name;
            log.LogWarning("Tunnel provisioning failed ({Error}); retry in {Delay}", _lastTunnelError, delay);
            Set(Layers.Tunnel, CheckState.Failed, _lastTunnelError);
        }
    }

    private Core.Vpn.Endpoint ResolvedEndpoint(VpnSettings vpn)
    {
        if (vpn.Endpoint.IsIpLiteral)
        {
            return vpn.Endpoint;
        }
        var cached = ParseAddresses(_state.EndpointAddresses).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        if (cached is not null)
        {
            return new Core.Vpn.Endpoint(cached.ToString(), vpn.Endpoint.Port);
        }
        return vpn.EndpointFallback ?? throw new TunnelException("endpoint_unresolved");
    }

    private async Task CheckTunnelAsync(string token, DateTimeOffset now, CancellationToken ct)
    {
        TunnelStatus status;
        try
        {
            status = await TunnelController.QueryAsync(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TunnelException or TimeoutException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Set(Layers.Tunnel, CheckState.Failed, e is TunnelException te ? te.Code : "query_failed");
            return;
        }
        if (!status.Installed)
        {
            Set(Layers.Tunnel, CheckState.Failed, _lastTunnelError ?? "not_installed");
            return;
        }
        if (!status.Running)
        {
            Set(Layers.Tunnel, CheckState.Failed, "stopped");
            if (_tunnelBackoff.CanAttempt(now))
            {
                try
                {
                    tunnel.Start();
                    _reconnects++;
                    log.LogInformation("Tunnel service started");
                }
                catch (Exception e) when (e is TunnelException or InvalidOperationException)
                {
                    log.LogWarning("Tunnel start failed; retry in {Delay}", _tunnelBackoff.Failed(now));
                }
            }
            return;
        }

        _lastHandshake = status.LatestHandshake;
        if (status.LatestHandshake is { } hs && now - hs < HandshakeFresh)
        {
            _staleSince = null;
            _noHandshakeSince = null;
            _tunnelBackoff.Succeeded();
            Set(Layers.Tunnel, CheckState.Ok, "handshake");
            if (!_tunnelUpThisRun)
            {
                _tunnelUpThisRun = true;
                _nextServerSync = _nextVerify = _nextDataProbe = DateTimeOffset.MinValue;     // prove the rest now
            }
            return;
        }

        Set(Layers.Tunnel, CheckState.Failed, status.LatestHandshake is null ? "no_handshake" : "stale_handshake");
        _staleSince ??= now;
        _noHandshakeSince ??= now;
        if (now - _staleSince > StaleBeforeRestart && _tunnelBackoff.CanAttempt(now))
        {
            try
            {
                tunnel.Restart();
                _reconnects++;
                _staleSince = null;
                log.LogInformation("No fresh handshake; tunnel restarted");
            }
            catch (Exception e) when (e is TunnelException or InvalidOperationException)
            {
                log.LogWarning("Tunnel restart failed");
            }
            _tunnelBackoff.Failed(now);
        }
        if (now - _noHandshakeSince > RekeyAfterNoHandshake && _apiReachable)
        {
            await MaybeRekeyAsync(token, force: false, ct).ConfigureAwait(false);
        }
    }

    private async Task MaybeRekeyAsync(string token, bool force, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (_state.LastRekeyAttempt is { } last && now - last < RekeyMinInterval)
        {
            return;
        }
        _state.LastRekeyAttempt = now;
        _state.Save();
        try
        {
            using var api = CreateApi();
            using var keys = WireGuardKeys.Generate();
            var bundle = await api.RekeyAsync(token, keys.PublicKey, ct).ConfigureAwait(false);
            SecretStore.Put(SecretStore.PrivateKey, keys.PrivateKeyBase64());
            SecretStore.Put(SecretStore.VpnJson, bundle.VpnJson);
            _state.VpnFingerprint = null;           // forces a new tunnel configuration
            _state.Save();
            _noHandshakeSince = null;
            log.LogInformation("VPN key rotated (reason: {Reason})", force ? "local key missing" : "no handshake");
        }
        catch (ApiException e)
        {
            log.LogWarning("Re-key failed: {Kind} {Status}", e.Kind, e.Status);
        }
    }

    // ------------------------------------------------------------------ CA

    private void EnsureCaTrusted()
    {
        if (!Consent.CertificateTrust)
        {
            Set(Layers.CaTrust, CheckState.Failed, "consent_missing");
            return;
        }
        var pem = SecretStore.Get(SecretStore.CaPem);
        if (pem is null || _state.CurrentCaSha256 is null)
        {
            Set(Layers.CaTrust, CheckState.Failed, "ca_missing");
            return;
        }
        try
        {
            var ca = CaCertificateValidator.Validate(new CaInfo(pem, _state.CurrentCaSha256, ""), ProductConfig.Current.ExpectedCaSha256,
                DateTimeOffset.UtcNow);
            using var cert = ca.Load();
            if (!TrustStore.IsTrusted(cert.Thumbprint))
            {
                var tp = trust.Add(ca);
                if (!_state.TrustedCaThumbprints.Contains(tp, StringComparer.OrdinalIgnoreCase))
                {
                    _state.TrustedCaThumbprints.Add(tp);
                    _state.Save();
                }
            }
            Set(Layers.CaTrust, CheckState.Ok, "trusted");
        }
        catch (CaValidationException e)
        {
            log.LogError("Stored filtering CA is not valid: {Reason}", e.Message);
            Set(Layers.CaTrust, CheckState.Failed, "ca_invalid");
        }
        catch (System.Security.Cryptography.CryptographicException e)
        {
            log.LogError(e, "Could not update the machine trust store");
            Set(Layers.CaTrust, CheckState.Failed, "store_error");
        }
    }

    // ------------------------------------------------------------------ server, data, verification

    private async Task DataProbeAsync(DateTimeOffset now, CancellationToken ct)
    {
        _nextDataProbe = now + DataProbeEvery;
        var failure = await NetworkVerifier.HttpDataAsync(ProbeTargets.HttpData, ct).ConfigureAwait(false);
        _dataOk = failure is null;
        _dataError = failure;
        if (failure is null)
        {
            _dataFailsInRow = 0;
            _dataFailSince = null;
            _dataRestartBackoff.Succeeded();
            return;
        }
        _dataFails++;
        _dataFailsInRow++;
        _dataFailSince ??= now;
        log.LogWarning("Tunnel is up but traffic failed ({Failure}, {Count} in a row)", failure, _dataFailsInRow);
        if (_dataFailsInRow >= 2 && _dataRestartBackoff.CanAttempt(now))
        {
            _dataRestartBackoff.Failed(now);
            try
            {
                tunnel.Restart();
                _reconnects++;
            }
            catch (Exception e) when (e is TunnelException or InvalidOperationException)
            {
                log.LogWarning("Tunnel restart after failed traffic check did not succeed");
            }
        }
    }

    private async Task ServerSyncAsync(string token, VpnSettings vpn, bool tunnelOk, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            using var api = CreateApi();
            var device = await api.GetDeviceAsync(token, ct).ConfigureAwait(false);
            _apiReachable = true;
            _apiBackoff.Succeeded();
            _state.ServerStatus = device.Status;
            _state.ServerMessage = device.Message;
            _state.LevelName = device.LevelName;
            _state.DeviceName = device.Name;
            _state.HeartbeatIntervalSeconds = device.HeartbeatIntervalSeconds;
            if (device.SupportWhatsApp.Length > 0)
            {
                _state.SupportWhatsApp = device.SupportWhatsApp;
            }

            // The server's own observation: the request arrived from this device's tunnel address.
            if (tunnelOk && device.ViaVpn == true)
            {
                Set(Layers.ServerPath, _dataOk == false ? CheckState.Failed : CheckState.Ok, _dataOk == false ? "no_traffic" : "via_vpn");
                if (!_state.TunnelEverVerified || !_state.NetworkLockEnabled)
                {
                    _state.TunnelEverVerified = true;
                    if (Consent.NetworkLock)
                    {
                        // From now on the computer fails closed.
                        await RefreshAddressCacheAsync(vpn, ct).ConfigureAwait(false);
                        _state.NetworkLockEnabled = true;
                        log.LogInformation("Tunnel verified by the server; enabling the network lock");
                    }
                }
                await RefreshAddressCacheAsync(vpn, ct).ConfigureAwait(false);
            }
            else if (tunnelOk)
            {
                Set(Layers.ServerPath, CheckState.Failed, "not_via_vpn");
            }
            else
            {
                Set(Layers.ServerPath, CheckState.Pending, "tunnel_down");
            }

            var hb = await api.HeartbeatAsync(token, BuildHeartbeat(now), ct).ConfigureAwait(false);
            _state.PolicyVersion = hb.PolicyVersion ?? _state.PolicyVersion;
            _state.ServerStatus = hb.Status.Length > 0 ? hb.Status : _state.ServerStatus;
            ApplyServerControls(hb);
            _state.Save();
            var interval = TimeSpan.FromSeconds(Math.Min(hb.IntervalSeconds, _state.HeartbeatIntervalSeconds));
            // Until everything is verified, check back sooner.
            _nextServerSync = now + (_snapshot.Overall == OverallState.Protected ? interval : TimeSpan.FromMinutes(2));
        }
        catch (ApiException e)
        {
            _apiReachable = !e.IsTransient;
            if (e.Kind == ApiErrorKind.Unauthorized)
            {
                // The device was removed on the server. Protection stays in place (fail closed); the user is told.
                _state.ServerStatus = "unauthorized";
                _state.Save();
                _nextServerSync = now + TimeSpan.FromMinutes(15);
            }
            else if (e.Kind == ApiErrorKind.Forbidden)
            {
                _nextServerSync = now + TimeSpan.FromMinutes(5);
            }
            else
            {
                var delay = _apiBackoff.Failed(now);
                _nextServerSync = now + delay;
                log.LogWarning("Server sync failed ({Kind} {Status}); retry in {Delay}", e.Kind, e.Status, delay);
            }
            if (e.IsTransient)
            {
                Set(Layers.ServerPath, CheckState.Failed, "api_unreachable");
            }
        }
    }

    private async Task RefreshVpnAsync(string token, VpnSettings current, string privateKey, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            using var api = CreateApi();
            var bundle = await api.GetVpnAsync(token, ct).ConfigureAwait(false);
            _nextVpnRefresh = now + VpnRefreshEvery;
            if (bundle.Vpn.Fingerprint() != current.Fingerprint())
            {
                SecretStore.Put(SecretStore.VpnJson, bundle.VpnJson);
                _state.VpnFingerprint = null;
                _state.TunnelAddress = bundle.Vpn.TunnelIPv4.ToString();
                _state.Save();
                log.LogInformation("Server VPN settings changed; tunnel will be reconfigured");
            }
            if (bundle.Ca is { } ca)
            {
                RotateCaIfNeeded(ca);
            }
            _ = privateKey;
        }
        catch (ApiException e)
        {
            _nextVpnRefresh = now + (e.IsTransient ? TimeSpan.FromMinutes(15) : VpnRefreshEvery);
            if (e.Kind == ApiErrorKind.InvalidResponse)
            {
                // A configuration that fails validation is never applied; the current one stays.
                log.LogError("Server returned an invalid VPN configuration; keeping the current one");
            }
        }
    }

    private void RotateCaIfNeeded(CaInfo ca)
    {
        if (ca.Sha256 == _state.CurrentCaSha256)
        {
            return;
        }
        try
        {
            var validated = CaCertificateValidator.Validate(ca, ProductConfig.Current.ExpectedCaSha256, DateTimeOffset.UtcNow);
            SecretStore.Put(SecretStore.CaPem, ca.Pem);
            _state.CurrentCaSha256 = validated.Sha256;
            _state.Save();
            // The new CA is trusted on the next tick; the old one is removed after interception is verified with the new one.
            log.LogInformation("Filtering CA rotation detected (new sha256 {Sha})", validated.Sha256[..16]);
            _nextVerify = DateTimeOffset.MinValue;
        }
        catch (CaValidationException e)
        {
            log.LogError("Rotated CA rejected: {Reason}", e.Message);
        }
    }

    public async Task VerifyFilteringAsync(DateTimeOffset now, CancellationToken ct)
    {
        _nextVerify = now + VerifyEvery;
        var ca = _state.CurrentCaSha256 ?? string.Empty;
        var probes = new List<TlsProbeOutcome>();
        foreach (var url in ProbeTargets.Interception)
        {
            probes.Add(await NetworkVerifier.HttpsAsync(url, asImage: false, ct).ConfigureAwait(false));
        }
        var interception = VerificationEvaluator.Interception(probes, ca);
        Set(Layers.Interception, interception.State, interception.Code);
        var image = await NetworkVerifier.HttpsAsync(ProbeTargets.Image, asImage: true, ct).ConfigureAwait(false);
        var imageVerdict = VerificationEvaluator.ImagePath(image, ca);
        Set(Layers.ImagePath, imageVerdict.State, imageVerdict.Code);
        log.LogInformation("Filtering verification: interception={I} image={Img}", interception.Code, imageVerdict.Code);
        if (interception.State == CheckState.Ok && imageVerdict.State == CheckState.Ok)
        {
            _lastVerified = now;
            _state.ProtectedSince ??= now;
            // CA rotation completes only once the new CA is proven: remove CAs we added that are no longer current.
            RemoveRetiredCas();
        }
        else
        {
            _nextVerify = now + TimeSpan.FromMinutes(2);
        }
    }

    private void RemoveRetiredCas()
    {
        var pem = SecretStore.Get(SecretStore.CaPem);
        if (pem is null || _state.TrustedCaThumbprints.Count <= 1)
        {
            return;
        }
        try
        {
            var current = CaCertificateValidator.Validate(new CaInfo(pem, _state.CurrentCaSha256 ?? "", ""), "", DateTimeOffset.UtcNow);
            using var cert = current.Load();
            var retired = _state.TrustedCaThumbprints.Where(t => !t.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase)).ToList();
            trust.Remove(retired);
            _state.TrustedCaThumbprints = [cert.Thumbprint];
            _state.Save();
        }
        catch (CaValidationException)
        {
        }
    }

    private async Task EnsureChromeOnlyAsync(DateTimeOffset now, CancellationToken ct)
    {
        Set(Layers.ChromePolicy, ChromeOnlyEnforcer.MachinePoliciesApplied() ? CheckState.Ok : CheckState.Pending,
            ChromeOnlyEnforcer.MachinePoliciesApplied() ? "applied" : "not_applied");
        if (!_policyBackoff.CanAttempt(now))
        {
            return;
        }
        try
        {
            var current = _checks.TryGetValue(Layers.ChromeOnly, out var c) ? c : LayerCheck.Unknown(Layers.ChromeOnly);
            // (On Windows Home nothing is applied, so "turned off from the dashboard" is final until the choice changes.)
            var offOnHome = _state.AppLockerMode is null && current is { State: CheckState.Ok, Code: "disabled_by_admin" };
            if ((_state.AppLockerMode is null && !offOnHome) || current.State == CheckState.Failed || ChromeOnlyEnforcer.PolicyOutdated(_state))
            {
                var applied = await chromeOnly.ApplyAsync(_state, ct).ConfigureAwait(false);
                Set(Layers.ChromeOnly, applied.State, applied.Code);
                Set(Layers.ChromePolicy, ChromeOnlyEnforcer.MachinePoliciesApplied() ? CheckState.Ok : CheckState.Failed, "applied");
                if (applied.State is CheckState.Failed or CheckState.Unsupported)
                {
                    var store = await chromeOnly.VerifyStoreAsync(_state, applied, ct).ConfigureAwait(false);
                    Set(Layers.StoreBlock, store.State, store.Code);
                    _policyBackoff.Failed(now);
                    return;
                }
                _nextChromeVerify = DateTimeOffset.MinValue;
            }
            if (now >= _nextChromeVerify)
            {
                var verified = await chromeOnly.VerifyAsync(_state, ct).ConfigureAwait(false);
                Set(Layers.ChromeOnly, verified.State, verified.Code);
                var store = await chromeOnly.VerifyStoreAsync(_state, verified, ct).ConfigureAwait(false);
                Set(Layers.StoreBlock, store.State, store.Code);
                _nextChromeVerify = now + (verified.State == CheckState.Ok ? VerifyEvery : TimeSpan.FromMinutes(1));
                if (verified.State == CheckState.Ok)
                {
                    _policyBackoff.Succeeded();
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or TimeoutException
                                      or System.ComponentModel.Win32Exception)
        {
            log.LogWarning(e, "Chrome-only enforcement step failed");
            Set(Layers.ChromeOnly, CheckState.Failed, "error");
            _policyBackoff.Failed(now);
        }
    }

    // ------------------------------------------------------------------ enrolment (from the UI)

    public async Task EnrollAsync(string code, string deviceName, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_state.Enrolled && _state.ServerStatus != "unauthorized")
            {
                throw new EnrollmentException("already_enrolled");
            }
            if (!TunnelController.WireGuardInstalled)
            {
                throw new EnrollmentException("wireguard_missing");
            }
            using var keys = WireGuardKeys.Generate();
            using var api = CreateApi();
            if (_state.Registration is not null)
            {
                // An activation code replaces a registration that was still waiting.
                await WithdrawRegistrationAsync(api, ct).ConfigureAwait(false);
            }
            EnrollmentResult result;
            try
            {
                result = await api.EnrollAsync(code, keys.PublicKey, deviceName.Length > 0 ? deviceName : "מחשב Windows",
                    _state.DeviceUid, ct).ConfigureAwait(false);
            }
            catch (ApiException e)
            {
                throw new EnrollmentException(e.Kind switch
                {
                    ApiErrorKind.Forbidden => "invalid_code",
                    ApiErrorKind.RateLimited => "rate_limited",
                    ApiErrorKind.Conflict => "conflict",
                    ApiErrorKind.Network or ApiErrorKind.Timeout or ApiErrorKind.Tls => "network",
                    _ => "server",
                }, e.ServerMessage);
            }
            ValidatedCa ca;
            try
            {
                ca = CaCertificateValidator.Validate(result.Ca, ProductConfig.Current.ExpectedCaSha256, DateTimeOffset.UtcNow);
            }
            catch (CaValidationException e)
            {
                log.LogError("Enrolment CA rejected: {Reason}", e.Message);
                throw new EnrollmentException("ca_invalid");
            }

            SecretStore.Put(SecretStore.PrivateKey, keys.PrivateKeyBase64());
            SecretStore.Put(SecretStore.Token, result.Token);
            SecretStore.Put(SecretStore.VpnJson, result.VpnJson);
            SecretStore.Put(SecretStore.CaPem, result.Ca.Pem);
            _state.Enrolled = true;
            _state.DeviceId = result.DeviceId;
            _state.DeviceName = deviceName;
            _state.LevelName = result.LevelName;
            _state.ServerStatus = result.Status;
            _state.ServerMessage = null;
            _state.TunnelAddress = result.Vpn.TunnelIPv4.ToString();
            _state.CurrentCaSha256 = ca.Sha256;
            _state.VpnFingerprint = null;
            await RefreshAddressCacheAsync(result.Vpn, ct).ConfigureAwait(false);
            _state.Save();
            _nextServerSync = _nextVerify = _nextDataProbe = _nextVpnRefresh = DateTimeOffset.MinValue;
            _nextVpnRefresh = DateTimeOffset.UtcNow + VpnRefreshEvery;
            log.LogInformation("Enrolled as device {Id}", result.DeviceId);
        }
        finally
        {
            _gate.Release();
            Wake();
        }
    }

    // ------------------------------------------------------------------ registration (from the UI)

    /// <summary>The registration form's levels and options, from the server (cached for 10 minutes).</summary>
    public async Task<Catalog> CatalogAsync(CancellationToken ct)
    {
        if (_catalog is { } c && DateTimeOffset.UtcNow - c.At < TimeSpan.FromMinutes(10))
        {
            return c.Catalog;
        }
        using var api = CreateApi();
        var fresh = await api.GetCatalogAsync(ct).ConfigureAwait(false);
        _catalog = (fresh, DateTimeOffset.UtcNow);
        return fresh;
    }

    /// <summary>
    /// Sends a registration request, like the phone app's "הצטרפות לשירות". The PC keeps a device token and its
    /// WireGuard key, but nothing is filtered or blocked until the administrator approves the request in the
    /// dashboard; then the service activates protection by itself (<see cref="RegistrationTickAsync"/>).
    /// </summary>
    public async Task RegisterAsync(RegistrationForm form, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(form);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_state.Enrolled && _state.ServerStatus != "unauthorized")
            {
                throw new EnrollmentException("already_enrolled");
            }
            if (_state.Registration is { Status: "pending" })
            {
                throw new EnrollmentException(Core.Ipc.IpcProtocol.Errors.AlreadyRegistered);
            }
            if (!TunnelController.WireGuardInstalled)
            {
                throw new EnrollmentException("wireguard_missing");
            }
            using var api = CreateApi();
            if (_state.Registration is not null)
            {
                await WithdrawRegistrationAsync(api, ct).ConfigureAwait(false);   // a refused request is replaced
            }
            using var keys = WireGuardKeys.Generate();
            var deviceName = form.DeviceName.Trim().Length > 0 ? form.DeviceName.Trim() : "מחשב Windows";
            RegistrationResult result;
            try
            {
                result = await api.RegisterAsync(form with { DeviceName = deviceName }, keys.PublicKey, _state.DeviceUid, ct)
                    .ConfigureAwait(false);
            }
            catch (ApiException e)
            {
                throw new EnrollmentException(e.Kind switch
                {
                    ApiErrorKind.Forbidden => Core.Ipc.IpcProtocol.Errors.RegistrationClosed,
                    ApiErrorKind.RateLimited => "rate_limited",
                    ApiErrorKind.Conflict => "conflict",
                    ApiErrorKind.BadRequest => "bad_request",
                    ApiErrorKind.Network or ApiErrorKind.Timeout or ApiErrorKind.Tls => "network",
                    _ => "server",
                }, e.ServerMessage);
            }
            SecretStore.Put(SecretStore.PrivateKey, keys.PrivateKeyBase64());
            SecretStore.Put(SecretStore.Token, result.Token);
            _state.Enrolled = false;
            _state.DeviceId = result.DeviceId;
            _state.DeviceName = deviceName;
            _state.ServerStatus = result.Status;
            _state.ServerMessage = null;
            _state.Registration = new PendingRegistration
            {
                Status = "pending",
                Message = result.Message,
                RequestId = result.RequestId,
                Name = form.Name.Trim(),
                Phone = form.Phone.Trim(),
                Email = form.Email.Trim(),
                Level = form.Level,
                Options = [.. form.Options],
                Note = form.Note.Trim(),
                SubmittedAt = DateTimeOffset.UtcNow,
            };
            _state.Save();
            _nextRegistrationCheck = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(20);
            log.LogInformation("Registration request {Request} sent (device {Id}); waiting for the administrator",
                result.RequestId, result.DeviceId);
        }
        finally
        {
            _gate.Release();
            Publish();
            Wake();
        }
    }

    /// <summary>Withdraws a registration that was not approved yet (also a refused one).</summary>
    public async Task CancelRegistrationAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_state.Enrolled || _state.Registration is null)
            {
                return;
            }
            using var api = CreateApi();
            await WithdrawRegistrationAsync(api, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            Publish();
            Wake();
        }
    }

    /// <summary>Caller holds the gate. Best effort on the server; always forgets the request locally.</summary>
    private async Task WithdrawRegistrationAsync(FilterPhoneApiClient api, CancellationToken ct)
    {
        if (SecretStore.Get(SecretStore.Token) is { } token && !_state.Enrolled)
        {
            try
            {
                await api.CancelRegistrationAsync(token, ct).ConfigureAwait(false);
            }
            catch (ApiException e)
            {
                log.LogInformation("Registration cancel on the server: {Kind}", e.Kind);
            }
        }
        SecretStore.Delete(SecretStore.Token);
        SecretStore.Delete(SecretStore.PrivateKey);
        _state.Registration = null;
        _state.DeviceId = null;
        _state.ServerStatus = null;
        _state.ServerMessage = null;
        _state.Save();
        log.LogInformation("Registration withdrawn");
    }

    /// <summary>
    /// While a registration waits: asks the server every ~30 seconds. When the administrator approved it, fetches
    /// the VPN settings and the filtering CA (validated like an activation-code enrolment) and switches to normal
    /// protection; from then on everything is as if the PC had been activated with a code.
    /// </summary>
    private async Task RegistrationTickAsync(CancellationToken ct)
    {
        var reg = _state.Registration;
        var now = DateTimeOffset.UtcNow;
        if (reg is not { Status: "pending" } || now < _nextRegistrationCheck)
        {
            return;
        }
        var token = SecretStore.Get(SecretStore.Token);
        if (token is null)
        {
            _state.Registration = null;
            _state.Save();
            return;
        }
        _nextRegistrationCheck = now + TimeSpan.FromSeconds(30);
        using var api = CreateApi();
        try
        {
            var device = await api.GetDeviceAsync(token, ct).ConfigureAwait(false);
            _apiReachable = true;
            reg.LastChecked = now;
            reg.Message = device.Message;
            _state.ServerStatus = device.Status;
            switch (device.Status)
            {
                case "active":
                    await CompleteApprovalAsync(api, token, device, ct).ConfigureAwait(false);
                    break;
                case "rejected":
                    reg.Status = "rejected";
                    log.LogInformation("Registration was not approved");
                    break;
            }
        }
        catch (ApiException e) when (e.Kind == ApiErrorKind.Unauthorized)
        {
            reg.Status = "rejected";
            reg.Message = "הבקשה כבר לא קיימת בשרת. אפשר לשלוח בקשה חדשה.";
        }
        catch (ApiException e)
        {
            _apiReachable = !e.IsTransient;
            _nextRegistrationCheck = now + TimeSpan.FromMinutes(1);
            log.LogInformation("Registration check failed ({Kind}); retrying", e.Kind);
        }
        catch (CaValidationException e)
        {
            log.LogError("Approved, but the filtering CA was rejected: {Reason}", e.Message);
            reg.Message = "החיבור אושר, אבל תעודת הסינון שהתקבלה לא עברה בדיקה. פנו לתמיכה.";
            _nextRegistrationCheck = now + TimeSpan.FromMinutes(5);
        }
        _state.Save();
    }

    private async Task CompleteApprovalAsync(FilterPhoneApiClient api, string token, DeviceInfo device, CancellationToken ct)
    {
        var bundle = await api.GetVpnAsync(token, ct).ConfigureAwait(false);
        var caInfo = bundle.Ca ?? throw new CaValidationException("the server sent no filtering CA");
        var ca = CaCertificateValidator.Validate(caInfo, ProductConfig.Current.ExpectedCaSha256, DateTimeOffset.UtcNow);
        SecretStore.Put(SecretStore.VpnJson, bundle.VpnJson);
        SecretStore.Put(SecretStore.CaPem, caInfo.Pem);
        _state.Enrolled = true;
        _state.Registration = null;
        _state.DeviceId = device.DeviceId;
        _state.DeviceName = device.Name.Length > 0 ? device.Name : _state.DeviceName;
        _state.LevelName = device.LevelName;
        _state.ServerStatus = device.Status;
        _state.ServerMessage = null;
        _state.TunnelAddress = bundle.Vpn.TunnelIPv4.ToString();
        _state.CurrentCaSha256 = ca.Sha256;
        _state.VpnFingerprint = null;
        await RefreshAddressCacheAsync(bundle.Vpn, ct).ConfigureAwait(false);
        _state.Save();
        _nextServerSync = _nextVerify = _nextDataProbe = DateTimeOffset.MinValue;
        _nextVpnRefresh = DateTimeOffset.UtcNow + VpnRefreshEvery;
        log.LogInformation("Registration approved: device {Id} activated", device.DeviceId);
        Wake();
    }

    public async Task<ProtectionSnapshot> VerifyNowAsync(CancellationToken ct)
    {
        _nextServerSync = _nextVerify = _nextDataProbe = _nextChromeVerify = DateTimeOffset.MinValue;
        _apiBackoff.Succeeded();
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await TickAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            Publish();
        }
        return _snapshot;
    }

    public void ReconnectNow()
    {
        if (TunnelController.IsInstalled())
        {
            try
            {
                tunnel.Restart();
                _reconnects++;
            }
            catch (Exception e) when (e is TunnelException or InvalidOperationException)
            {
                log.LogWarning("Manual reconnect failed");
            }
        }
        _nextServerSync = _nextVerify = _nextDataProbe = DateTimeOffset.MinValue;
        Wake();
    }

    public string Diagnostics() =>
        DiagnosticReport.Build(_snapshot, ServiceLog.Instance?.Recent() ?? [], DateTimeOffset.UtcNow);

    // ------------------------------------------------------------------ helpers

    private FilterPhoneApiClient CreateApi() => new(ProductConfig.Current.ApiBaseUrl, ResolveApiAsync);

    /// <summary>System DNS first; while the network lock blocks DNS outside the tunnel, the cached addresses.</summary>
    private async ValueTask<IPAddress[]> ResolveApiAsync(string host, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(4));
            var found = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            if (found.Length > 0)
            {
                return found;
            }
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            if (ct.IsCancellationRequested)
            {
                throw;
            }
        }
        var cached = ParseAddresses(_state.ApiAddresses).ToArray();
        return cached.Length > 0 ? cached : throw new SocketException((int)SocketError.HostNotFound);
    }

    private async Task RefreshAddressCacheAsync(VpnSettings vpn, CancellationToken ct)
    {
        async Task<List<string>> Resolve(string host)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                return (await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false))
                    .Where(a => !IPAddress.IsLoopback(a) && !a.Equals(IPAddress.Any)).Select(a => a.ToString()).Distinct().Take(8).ToList();
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                return [];
            }
        }
        if (!vpn.Endpoint.IsIpLiteral)
        {
            var ep = await Resolve(vpn.Endpoint.Host).ConfigureAwait(false);
            if (ep.Count > 0)
            {
                _state.EndpointAddresses = ep;
            }
        }
        var apiHost = ProductConfig.Current.ApiBaseUrl.Host;
        if (!IPAddress.TryParse(apiHost, out _))
        {
            var apiAddrs = await Resolve(apiHost).ConfigureAwait(false);
            if (apiAddrs.Count > 0)
            {
                _state.ApiAddresses = apiAddrs;
            }
        }
        _state.Save();
    }

    private static List<IPAddress> ParseAddresses(IEnumerable<string> list) =>
        list.Select(s => IPAddress.TryParse(s, out var a) ? a : null).OfType<IPAddress>().ToList();

    /// <summary>The dashboard's choices for this PC and, once, the key that verifies its removal codes.</summary>
    private void ApplyServerControls(HeartbeatResult hb)
    {
        if (hb.Controls is { } controls && Choices.Save(controls))
        {
            log.LogInformation("Dashboard settings changed: Chrome only {Chrome}, Store blocked {Store}",
                controls.ChromeOnly, controls.BlockStore);
            _nextChromeVerify = DateTimeOffset.MinValue;      // re-apply and re-verify now
            _policyBackoff.Succeeded();
            Set(Layers.ChromeOnly, CheckState.Pending, "not_applied");
        }
        if (hb.RemovalKey is { } key && !SecretStore.Has(SecretStore.RemovalKey))
        {
            SecretStore.Put(SecretStore.RemovalKey, key);
            log.LogInformation("Removal-code key received; removing FilterPhone now needs a code from the dashboard");
        }
    }

    /// <summary>
    /// Checks a removal code from the dashboard. A valid code authorizes the uninstaller for a short time; it
    /// changes nothing else (protection keeps running until the uninstaller removes it).
    /// </summary>
    internal async Task<RemovalAuthorization> AuthorizeRemovalAsync(string code, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = DateTimeOffset.UtcNow;
            if (!RemovalGate.CodeRequired(_state))
            {
                return RemovalAuthorization.NotRequired;
            }
            if (_state.DeviceId is not int id || !RemovalCode.Verify(SecretStore.Get(SecretStore.RemovalKey), id, code, now))
            {
                log.LogWarning("Removal code rejected");
                return RemovalAuthorization.WrongCode;
            }
            _state.RemovalAuthorizedUntil = now + RemovalPolicy.AuthorizationLifetime;
            _state.Save();
            log.LogWarning("Removal authorized with a code from the dashboard (valid for {Minutes} minutes)",
                (int)RemovalPolicy.AuthorizationLifetime.TotalMinutes);
            return RemovalAuthorization.Authorized;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string StateWord(CheckState s) => s switch
    {
        CheckState.Ok => "ok",
        CheckState.Pending => "pending",
        CheckState.Failed => "failed",
        CheckState.Unsupported => "unsupported",
        _ => "unknown",
    };

    private HeartbeatReport BuildHeartbeat(DateTimeOffset now)
    {
        var tunnelOk = _checks.TryGetValue(Layers.Tunnel, out var t) && t.State == CheckState.Ok;
        var layers = Layers.All.ToDictionary(l => l, l => StateWord(_checks.TryGetValue(l, out var c) ? c.State : CheckState.Unknown),
            StringComparer.Ordinal);
        return new HeartbeatReport
        {
            Windows = new WindowsReport(_snapshot.Overall.ToString(), WindowsInfo.EditionId, WindowsInfo.Build,
                _state.ProtectedSince?.ToUnixTimeSeconds(), layers),
            WantRemovalKey = !SecretStore.Has(SecretStore.RemovalKey),
            AppVersion = ProductConfig.Version,
            DeviceUid = _state.DeviceUid,
            PolicyVersion = _state.PolicyVersion,
            CaInstalled = _checks.TryGetValue(Layers.CaTrust, out var ca) ? ca.State == CheckState.Ok : null,
            VpnState = tunnelOk ? "UP" : "DOWN",
            HandshakeAgeSeconds = _lastHandshake is { } h ? (int)Math.Max(0, (now - h).TotalSeconds) : null,
            TunnelAutoStart = TunnelController.IsInstalled(),
            KillSwitchActive = _checks.TryGetValue(Layers.KillSwitch, out var k) && k.State == CheckState.Ok,
            Reconnects = _reconnects,
            VpnError = tunnelOk ? null : t?.Code,
            DataOk = _dataOk,
            DataError = _dataError,
            DataFails = _dataFails,
            DataFailAgeSeconds = _dataFailSince is { } f ? (int)(now - f).TotalSeconds : null,
        };
    }

    private void Set(string layer, CheckState state, string code) =>
        _checks[layer] = new LayerCheck(layer, state, code, DateTimeOffset.UtcNow);

    private void Publish()
    {
        var checks = Layers.All.ToDictionary(l => l, l => _checks.TryGetValue(l, out var c) ? c : LayerCheck.Unknown(l));
        var ctx = new EvaluationContext(_state.Enrolled,
            _state.ServerStatus == "unauthorized" ? "unauthorized" : _state.ServerStatus,
            _state.TunnelEverVerified || _tunnelUpThisRun, _apiReachable, DateTimeOffset.UtcNow)
        {
            Registration = _state.Enrolled ? null : _state.Registration?.Status,
        };
        var reg = _state.Enrolled ? null : _state.Registration;
        _snapshot = new ProtectionSnapshot
        {
            Overall = ProtectionEvaluator.Evaluate(checks, ctx),
            Checks = checks,
            DeviceId = _state.DeviceId,
            DeviceName = _state.DeviceName,
            LevelName = _state.LevelName,
            ServerStatus = _state.ServerStatus,
            ServerMessage = _state.ServerMessage,
            TunnelAddress = _state.TunnelAddress,
            LastHandshake = _lastHandshake,
            LastVerified = _lastVerified,
            ProtectedSince = _state.ProtectedSince,
            WindowsEdition = WindowsInfo.EditionId,
            WindowsBuild = WindowsInfo.Build,
            SupportWhatsApp = _state.SupportWhatsApp.Length > 0 ? _state.SupportWhatsApp : ProductConfig.Current.SupportWhatsApp,
            SupportEmailConfigured = ProductConfig.Current.SupportEmail.Length > 0,
            Registration = reg is null ? null : new RegistrationInfo
            {
                Status = reg.Status,
                Message = reg.Message,
                Name = reg.Name,
                Phone = reg.Phone,
                Email = reg.Email,
                Level = reg.Level,
                Options = [.. reg.Options],
                Note = reg.Note,
                SubmittedAt = reg.SubmittedAt,
                LastChecked = reg.LastChecked,
            },
        };
    }
}
