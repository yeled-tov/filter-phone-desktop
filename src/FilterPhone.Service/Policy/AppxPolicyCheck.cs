using FilterPhone.Service.Infrastructure;

namespace FilterPhone.Service.Policy;

/// <summary>
/// Asks Windows' own AppLocker engine (Test-AppLockerPolicy) how a policy decides for an installed packaged
/// app. Used to prove that the Store rule really matches the installed Microsoft Store package, and by the
/// Windows tests to prove the rule format against a real package.
/// </summary>
internal static class AppxPolicyCheck
{
    public const string NotInstalled = "NotInstalled";

    /// <summary>
    /// Returns "Allowed", "Denied", "DeniedByDefault" or <see cref="NotInstalled"/>, or null if the evaluation
    /// itself failed.
    /// </summary>
    public static async Task<string?> DecideAsync(string policyPath, string packageName, string? user, CancellationToken ct)
    {
        static string Quote(string s) => "'" + s.Replace("'", "''", StringComparison.Ordinal) + "'";
        var userArg = user is { Length: > 0 } ? " -User " + Quote(user) : string.Empty;
        var r = await ProcessRunner.RunAsync(ProcessRunner.PowerShell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             "Import-Module AppLocker; " +
             $"$p = Get-AppxPackage -AllUsers -Name {Quote(packageName)} | Select-Object -First 1; " +
             $"if ($null -eq $p) {{ '{NotInstalled}'; exit 0 }}; " +
             // -Packages takes a typed generic list of the Appx module's package objects.
             "$l = [Activator]::CreateInstance([System.Collections.Generic.List`1].MakeGenericType($p.GetType())); $l.Add($p); " +
             $"(Test-AppLockerPolicy -XmlPolicy {Quote(policyPath)} -Packages $l{userArg} | Select-Object -First 1).PolicyDecision"],
            TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        var output = r.StdOut.Trim();
        return r.ExitCode == 0 && output.Length > 0 ? output.Split('\n')[^1].Trim() : null;
    }
}
