using Microsoft.Win32;

namespace FilterPhone.Service.Policy;

internal enum AppControlSupport
{
    /// <summary>Enterprise / Education / IoT Enterprise / Server: AppLocker local policy is supported.</summary>
    LocalPolicy,
    /// <summary>Pro editions: try local policy, then the AppLocker CSP through the MDM WMI bridge; verified by probe.</summary>
    ProWithVerification,
    /// <summary>Home: AppLocker is not available.</summary>
    Unsupported,
}

internal static class WindowsInfo
{
    public static string EditionId => Read("EditionID") ?? "Unknown";
    public static string ProductName => Read("ProductName") ?? "Windows";
    public static string Build => Read("CurrentBuild") ?? Environment.OSVersion.Version.Build.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public static string DisplayVersion => Read("DisplayVersion") ?? string.Empty;

    public static AppControlSupport AppControl => Classify(EditionId);

    internal static AppControlSupport Classify(string editionId) => editionId switch
    {
        "Enterprise" or "EnterpriseN" or "EnterpriseS" or "EnterpriseSN" or "Education" or "EducationN"
            or "IoTEnterprise" or "IoTEnterpriseS" or "ServerStandard" or "ServerDatacenter" => AppControlSupport.LocalPolicy,
        "Professional" or "ProfessionalN" or "ProfessionalWorkstation" or "ProfessionalWorkstationN"
            or "ProfessionalEducation" or "ProfessionalEducationN" => AppControlSupport.ProWithVerification,
        _ => AppControlSupport.Unsupported,
    };

    private static string? Read(string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        return key?.GetValue(name) as string;
    }
}
