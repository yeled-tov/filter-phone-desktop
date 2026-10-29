using System.Threading;
using System.Windows;

namespace FilterPhone.App;

public partial class App : Application
{
    private Mutex? _single;

    protected override void OnStartup(StartupEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        if (e.Args is ["--authorize-removal"])
        {
            // Started by the uninstaller: ask for the removal code and report the result as the exit code.
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;     // the exit code is set only by the line below
            var removal = new RemovalWindow();
            MainWindow = removal;
            removal.Closed += (_, _) => Shutdown(removal.Authorized ? 0 : 1);
            removal.Show();
            return;
        }
        // One window per user session.
        _single = new Mutex(true, @"Local\FilterPhone.Desktop.App", out var first);
        if (!first)
        {
            Shutdown();
            return;
        }
        DispatcherUnhandledException += (_, args) =>
        {
            // Never show a stack trace to the user; the protection itself runs in the service.
            MessageBox.Show("אירעה תקלה בחלון FilterPhone. ההגנה במחשב ממשיכה לפעול. אפשר לפתוח את החלון מחדש.",
                "FilterPhone", MessageBoxButton.OK, MessageBoxImage.Warning, MessageBoxResult.OK,
                MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign);
            args.Handled = true;
        };
        base.OnStartup(e);
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _single?.Dispose();
        base.OnExit(e);
    }
}
