namespace FilterPhone.Service.Infrastructure;

/// <summary>Well-known locations. Everything under <see cref="DataRoot"/> is SYSTEM/Administrators only.</summary>
internal static class Paths
{
    public static string ProgramData => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    public static string ProgramFiles => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    public static string ProgramFilesX86 => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    public static string WindowsDir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    public static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);

    public static string DataRoot => Path.Combine(ProgramData, "FilterPhone");
    public static string Secrets => Path.Combine(DataRoot, "Secrets");
    public static string Tunnel => Path.Combine(DataRoot, "Tunnel");
    public static string Logs => Path.Combine(DataRoot, "Logs");
    public static string Policy => Path.Combine(DataRoot, "Policy");      // readable by users (default associations)
    public static string Probe => Path.Combine(DataRoot, "Probe");        // readable/executable by users (launch probe)
    public static string StateFile => Path.Combine(DataRoot, "state.json");

    public static string TunnelConfig => Path.Combine(Tunnel, Core.ProductConfig.TunnelName + ".conf.dpapi");
    public static string AppLockerPolicyFile => Path.Combine(DataRoot, "applocker-policy.xml");
    public static string DefaultAssociationsFile => Path.Combine(Policy, "DefaultAssociations.xml");
    public static string ProbeExecutable => Path.Combine(Probe, "fp-portable-probe.exe");

    public static string ServiceExecutable => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "FilterPhone.Service.exe");

    public static string WireGuardDir => Path.Combine(ProgramFiles, "WireGuard");
    public static string WireGuardExe => Path.Combine(WireGuardDir, "wireguard.exe");
    public static string WgExe => Path.Combine(WireGuardDir, "wg.exe");

    /// <summary>Consent recorded by the elevated installer (HKLM, administrators only).</summary>
    public const string ConsentKey = @"SOFTWARE\FilterPhone Desktop\Consent";
    public const string ServiceName = "FilterPhoneService";
}
