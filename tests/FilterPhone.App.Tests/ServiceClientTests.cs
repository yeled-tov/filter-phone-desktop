using System.Diagnostics;

namespace FilterPhone.App.Tests;

/// <summary>
/// The UI runs as a standard user and cannot read the image path of the SYSTEM service, so it identifies the pipe
/// server through the Service Control Manager instead (regression: every standard user saw "not FilterPhone").
/// </summary>
public sealed class ServiceClientTests
{
    private const string Expected = @"C:\Program Files\FilterPhone Desktop\FilterPhone.Service.exe";

    [Fact]
    public void Pipe_served_by_the_service_process_is_trusted_even_when_its_path_is_unreadable()
    {
        Assert.True(ServiceClient.IsTrustedServer(4242, servicePid: 4242, serverPath: null, Expected));
    }

    [Fact]
    public void Another_process_holding_the_pipe_is_not_trusted()
    {
        Assert.False(ServiceClient.IsTrustedServer(5000, servicePid: 4242, serverPath: null, Expected));
        Assert.False(ServiceClient.IsTrustedServer(5000, servicePid: 4242, serverPath: @"C:\Users\x\evil.exe", Expected));
        Assert.False(ServiceClient.IsTrustedServer(5000, servicePid: null, serverPath: null, Expected));
        Assert.False(ServiceClient.IsTrustedServer(0, servicePid: 0, serverPath: null, Expected));
    }

    [Fact]
    public void Installed_service_exe_is_trusted_when_its_path_is_readable()
    {
        Assert.True(ServiceClient.IsTrustedServer(5000, servicePid: null, serverPath: Expected.ToUpperInvariant(), Expected));
    }

    [Fact]
    public void Scm_reports_the_process_of_a_running_service()
    {
        // The Windows Event Log service always runs; any user may query its status.
        var pid = ServiceClient.RunningServicePid("EventLog");
        Assert.NotNull(pid);
        using var process = Process.GetProcessById((int)pid!.Value);
        Assert.False(process.HasExited);
    }

    [Fact]
    public void Missing_service_has_no_process()
    {
        Assert.Null(ServiceClient.RunningServicePid("FilterPhoneNoSuchService"));
    }
}
