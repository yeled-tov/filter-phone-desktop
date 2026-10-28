using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace FilterPhone.App;

public sealed record UpdateInfo(Version Version, Uri Url, string Sha256);

/// <summary>
/// Optional, owner-configured update check. An update is started only if the installer (1) is served over
/// HTTPS from the configured feed, (2) matches the SHA-256 stated in the manifest, and (3) carries a valid
/// Authenticode signature from the configured publisher. Windows then asks for UAC as usual.
/// Without a configured feed and publisher the app only shows its version.
/// </summary>
public static partial class Updater
{
    private static string Meta(string key) =>
        typeof(Updater).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == "FilterPhone." + key)?.Value ?? string.Empty;

    public static bool Configured => Uri.TryCreate(Meta("UpdateManifestUrl"), UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps
                                     && Meta("UpdatePublisher").Length > 0;

    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct)
    {
        if (!Configured)
        {
            return null;
        }
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20), MaxResponseContentBufferSize = 64 * 1024 };
        using var doc = JsonDocument.Parse(await http.GetStringAsync(new Uri(Meta("UpdateManifestUrl")), ct).ConfigureAwait(false));
        var r = doc.RootElement;
        if (!Version.TryParse(r.GetProperty("version").GetString(), out var v)
            || !Uri.TryCreate(r.GetProperty("url").GetString(), UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }
        var sha = r.GetProperty("sha256").GetString()?.ToLowerInvariant() ?? string.Empty;
        var current = Version.Parse(Core.ProductConfig.Version);
        return v > current && sha.Length == 64 ? new UpdateInfo(v, url, sha) : null;
    }

    public static async Task<bool> DownloadVerifyAndStartAsync(UpdateInfo update, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(update);
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FilterPhone", "Updates");
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "FilterPhone-Desktop-Setup.exe");
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) })
        await using (var fs = File.Create(file))
        {
            await using var s = await http.GetStreamAsync(update.Url, ct).ConfigureAwait(false);
            await s.CopyToAsync(fs, ct).ConfigureAwait(false);
        }
        await using (var fs = File.OpenRead(file))
        {
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false));
            if (hash != update.Sha256)
            {
                File.Delete(file);
                return false;
            }
        }
        if (!SignedBy(file, Meta("UpdatePublisher")))
        {
            File.Delete(file);
            return false;
        }
        Process.Start(new ProcessStartInfo(file) { UseShellExecute = true });
        return true;
    }

    private static unsafe bool SignedBy(string path, string publisher)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var file = new WinTrustFileInfo { cbStruct = (uint)sizeof(WinTrustFileInfo), pcwszFilePath = pathPtr };
            var data = new WinTrustData
            {
                cbStruct = (uint)sizeof(WinTrustData),
                dwUIChoice = 2,
                dwUnionChoice = 1,
                pFile = (IntPtr)(&file),
                dwStateAction = 1,
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            var result = WinVerifyTrust(new IntPtr(-1), &action, &data);
            data.dwStateAction = 2;
            _ = WinVerifyTrust(new IntPtr(-1), &action, &data);
            if (result != 0)
            {
                return false;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
        }
#pragma warning disable SYSLIB0057
        using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        return cert.GetNameInfo(X509NameType.SimpleName, false) == publisher || cert.Subject.Contains("O=" + publisher, StringComparison.Ordinal);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static unsafe partial int WinVerifyTrust(IntPtr hwnd, Guid* action, WinTrustData* data);
}
