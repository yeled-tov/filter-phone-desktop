using System.Windows;
using System.Windows.Threading;

namespace FilterPhone.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(5) };

    public MainWindow()
        : this(new MainViewModel(), live: true)
    {
    }

    /// <summary><paramref name="live"/> = false: a preview that never talks to the service (screenshots in CI).</summary>
    internal MainWindow(MainViewModel vm, bool live)
    {
        InitializeComponent();
        _vm = vm;
        DataContext = _vm;
        if (!live)
        {
            return;
        }
        _timer.Tick += async (_, _) => await _vm.RefreshAsync();
        Loaded += async (_, _) =>
        {
            await _vm.RefreshAsync();
            _timer.Start();
        };
        Closed += (_, _) => _timer.Stop();
    }
}
