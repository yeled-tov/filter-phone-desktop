using System.Windows;
using System.Windows.Threading;

namespace FilterPhone.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(5) };

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        _timer.Tick += async (_, _) => await _vm.RefreshAsync();
        Loaded += async (_, _) =>
        {
            await _vm.RefreshAsync();
            _timer.Start();
        };
        Closed += (_, _) => _timer.Stop();
    }
}
