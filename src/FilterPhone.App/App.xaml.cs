using System.Threading;
using System.Windows;

namespace FilterPhone.App;

public partial class App : Application
{
    private Mutex? _single;

    protected override void OnStartup(StartupEventArgs e)
    {
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
