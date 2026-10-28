using FilterPhone.Core;
using FilterPhone.Service;
using FilterPhone.Service.Engine;
using FilterPhone.Service.Infrastructure;
using FilterPhone.Service.Ipc;
using FilterPhone.Service.Policy;
using FilterPhone.Service.Trust;
using FilterPhone.Service.Tunnel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;

// Command-line modes are for the elevated installer/uninstaller and documented recovery only:
//   --cleanup              remove everything FilterPhone Desktop changed (uninstall)
//   --remove-network-lock  remove only the fail-closed network filters (recovery)
//   --status | --verify | --diagnostics | --enroll   talk to the running service (see Ipc/CliClient.cs)
//   --version
if (args.Length == 1 && args[0] == "--version")
{
    Console.WriteLine(ProductConfig.Version);
    return 0;
}
if (args.Length == 1 && args[0] is "--cleanup" or "--remove-network-lock")
{
    SecureDirectory.EnsureAll();
    var serviceLog = new ServiceLog(Paths.Logs);
    using var loggers = LoggerFactory.Create(b => b.AddProvider(serviceLog).AddSimpleConsole());
    return await Cleanup.RunAsync(loggers, networkLockOnly: args[0] == "--remove-network-lock").ConfigureAwait(false);
}
if (args.Length >= 1 && args[0] is "--status" or "--verify" or "--enroll" or "--diagnostics")
{
    return await FilterPhone.Service.Ipc.CliClient.RunAsync(args).ConfigureAwait(false);
}
if (args.Length > 0 || !WindowsServiceHelpers.IsWindowsService())
{
    Console.Error.WriteLine("FilterPhone.Service runs as the 'FilterPhoneService' Windows service.");
    Console.Error.WriteLine("Maintenance: --status | --verify | --diagnostics | --enroll | --cleanup | --remove-network-lock | --version");
    return 2;
}

SecureDirectory.EnsureAll();
var log = new ServiceLog(Paths.Logs);
ServiceLog.Instance = log;

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { ContentRootPath = AppContext.BaseDirectory });
builder.Services.AddWindowsService(o => o.ServiceName = Paths.ServiceName);
builder.Logging.ClearProviders();
builder.Logging.AddProvider(log);
builder.Services.Configure<HostOptions>(o =>
{
    // A failing background step is logged and retried inside the loop; it never stops the service.
    o.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
    o.ShutdownTimeout = TimeSpan.FromSeconds(20);
});
builder.Services.AddSingleton<TunnelController>();
builder.Services.AddSingleton<TrustStore>();
builder.Services.AddSingleton<ChromeOnlyEnforcer>();
builder.Services.AddSingleton<ProtectionEngine>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ProtectionEngine>());
builder.Services.AddHostedService<FilterPhone.Service.Policy.BrowserWatchdog>();
builder.Services.AddHostedService<PipeServer>();

await builder.Build().RunAsync().ConfigureAwait(false);
return 0;
