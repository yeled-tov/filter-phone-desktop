using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using FilterPhone.Core.Api;
using FilterPhone.Core.Status;

namespace FilterPhone.App.Tests;

/// <summary>
/// Renders each page of the app with realistic sample data (the server's real catalog) to PNG files, so the
/// design can be reviewed from the CI artifact, and fails if any binding in the XAML is broken.
/// </summary>
public sealed class ScreenshotTests
{
    private static readonly string OutDir = Environment.GetEnvironmentVariable("FP_SCREENS_DIR")
        ?? Path.Combine(AppContext.BaseDirectory, "screens");

    private sealed class BindingErrors : TraceListener
    {
        public List<string> Messages { get; } = [];
        public override void Write(string? message) { }
        public override void WriteLine(string? message)
        {
            if (message is not null)
            {
                Messages.Add(message);
            }
        }
    }

    private static Catalog SampleCatalog()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "catalog.json")));
        return Catalog.Parse(doc.RootElement);
    }

    private static Dictionary<string, LayerCheck> Checks(CheckState state, params (string Layer, CheckState State, string Code)[] overrides)
    {
        var now = DateTimeOffset.UtcNow;
        var d = Layers.All.ToDictionary(l => l, l => new LayerCheck(l, state, "applied", now));
        foreach (var (layer, s, code) in overrides)
        {
            d[layer] = new LayerCheck(layer, s, code, now);
        }
        return d;
    }

    private static void RunSta(Action action)
    {
        Exception? error = null;
        var t = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception e)
            {
                error = e;
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null)
        {
            throw new InvalidOperationException("Rendering failed: " + error.Message, error);
        }
    }

    private static void Render(MainViewModel vm, string name, double height = 860)
    {
        var window = new MainWindow(vm, live: false);
        var root = (FrameworkElement)window.Content;
        window.Content = null;
        var host = new Border
        {
            Child = root,
            DataContext = vm,
            FlowDirection = FlowDirection.RightToLeft,
            Background = (Brush)Application.Current!.Resources["Page"],
            Width = 760,
            Height = height,
        };
        TextElement.SetForeground(host, (Brush)Application.Current!.Resources["Ink"]);
        TextElement.SetFontFamily(host, new FontFamily("Segoe UI"));
        host.Measure(new Size(760, height));
        host.Arrange(new Rect(0, 0, 760, height));
        host.UpdateLayout();
        System.Windows.Threading.Dispatcher.CurrentDispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
        host.UpdateLayout();
        const double scale = 1.5;
        var bmp = new RenderTargetBitmap((int)(760 * scale), (int)(height * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        bmp.Render(host);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        Directory.CreateDirectory(OutDir);
        using var file = File.Create(Path.Combine(OutDir, name + ".png"));
        encoder.Save(file);
        window.Close();
    }

    [Fact]
    public void Every_page_renders_without_binding_errors()
    {
        var errors = new BindingErrors();
        RunSta(() =>
        {
            PresentationTraceSources.Refresh();
            PresentationTraceSources.DataBindingSource.Listeners.Add(errors);
            PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error;
            if (Application.Current is null)
            {
                var app = new App();
                app.InitializeComponent();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;    // closing a preview window must not end the app
            }
            var catalog = SampleCatalog();

            var vm = new MainViewModel();
            vm.ShowForPreview(AppScreen.Welcome);
            Render(vm, "01-welcome");

            vm = new MainViewModel();
            vm.Registration.Apply(catalog);
            vm.ShowForPreview(AppScreen.Register);
            Render(vm, "02-register-details");
            vm.Registration.Name = "משה כהן";
            vm.Registration.Phone = "050-1234567";
            vm.Registration.DeviceName = "המחשב בסלון";
            vm.Registration.Step = 1;
            Render(vm, "03-register-level");
            vm.Registration.Step = 2;
            foreach (var o in vm.Registration.Popular.Take(3))
            {
                o.IsSelected = true;
            }
            vm.Registration.Categories[2].IsExpanded = true;
            Render(vm, "04-register-blocks", 1300);
            vm.Registration.Note = "בבקשה לחסום גם את אתר החדשות שאני רגיל לקרוא";
            vm.Registration.Step = 3;
            Render(vm, "05-register-summary", 1000);

            vm = new MainViewModel();
            vm.ShowForPreview(AppScreen.Activation);
            Render(vm, "06-activation");

            var registration = new RegistrationInfo
            {
                Status = "pending",
                Message = "הבקשה התקבלה ומחכה לאישור. נעדכן ברגע שהחיבור ייפתח.",
                Name = "משה כהן",
                Phone = "050-1234567",
                Level = 1,
                Options = [.. catalog.ForPc.Where(o => o.Popular).Take(3).Select(o => o.Id)],
                Note = "גם יוטיוב",
                SubmittedAt = DateTimeOffset.UtcNow.AddMinutes(-3),
                LastChecked = DateTimeOffset.UtcNow.AddSeconds(-20),
            };
            vm = new MainViewModel();
            vm.Registration.Apply(catalog);
            vm.ApplyForPreview(new ProtectionSnapshot
            {
                Overall = OverallState.AwaitingApproval,
                Checks = Checks(CheckState.Unknown),
                Registration = registration,
            });
            Render(vm, "07-pending", 960);

            vm = new MainViewModel();
            vm.Registration.Apply(catalog);
            vm.ApplyForPreview(new ProtectionSnapshot
            {
                Overall = OverallState.RegistrationRejected,
                Checks = Checks(CheckState.Unknown),
                Registration = registration with { Status = "rejected", Message = "הבקשה לא אושרה. חסר מספר טלפון נוסף." },
            });
            Render(vm, "08-rejected");

            vm = new MainViewModel();
            vm.ApplyForPreview(new ProtectionSnapshot
            {
                Overall = OverallState.Protected,
                Checks = Checks(CheckState.Ok),
                DeviceId = 42,
                LevelName = "מחמיר",
                LastVerified = DateTimeOffset.UtcNow.AddMinutes(-4),
                WindowsEdition = "Professional",
                WindowsBuild = "22631",
            });
            Render(vm, "09-status-protected", 1000);

            vm = new MainViewModel();
            vm.ApplyForPreview(new ProtectionSnapshot
            {
                Overall = OverallState.ProtectedWithLimitations,
                Checks = Checks(CheckState.Ok, (Layers.ChromeOnly, CheckState.Unsupported, "edition_unsupported"),
                    (Layers.StoreBlock, CheckState.Unsupported, "store_closed_on_open")),
                DeviceId = 43,
                LevelName = "בינוני",
                LastVerified = DateTimeOffset.UtcNow.AddMinutes(-12),
                WindowsEdition = "Core",
                WindowsBuild = "19045",
            });
            Render(vm, "10-status-limited", 1000);

            var removal = new RemovalWindow();
            var content = (FrameworkElement)removal.Content!;
            removal.Content = null;
            var host = new Border
            {
                Child = content,
                Width = 500,
                FlowDirection = FlowDirection.RightToLeft,
                Background = (Brush)Application.Current!.Resources["Page"]
            };
            TextElement.SetForeground(host, (Brush)Application.Current!.Resources["Ink"]);
            host.Measure(new Size(500, double.PositiveInfinity));
            host.Arrange(new Rect(host.DesiredSize));
            var bmp = new RenderTargetBitmap((int)(500 * 1.5), (int)(host.DesiredSize.Height * 1.5), 144, 144, PixelFormats.Pbgra32);
            bmp.Render(host);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bmp));
            using var file = File.Create(Path.Combine(OutDir, "11-removal-code.png"));
            encoder.Save(file);
        });
        Assert.True(errors.Messages.Count == 0, "Binding errors:\n" + string.Join("\n", errors.Messages.Take(20)));
        Assert.True(File.Exists(Path.Combine(OutDir, "05-register-summary.png")));
    }

    [Fact]
    public void The_registration_form_offers_only_what_a_pc_can_block()
    {
        RunSta(() =>
        {
            var catalog = SampleCatalog();
            var reg = new RegistrationViewModel((_, _, _) => throw new InvalidOperationException("no service in tests"));
            reg.Apply(catalog);
            var offered = reg.Categories.SelectMany(c => c.Options).Select(o => o.Id).ToHashSet();
            Assert.Equal(catalog.ForPc.Select(o => o.Id).ToHashSet(), offered);
            Assert.DoesNotContain(catalog.Options.Where(o => o.AppliesToPc == false).Select(o => o.Id), offered.Contains);
            Assert.Equal(1, reg.SelectedLevel?.Level);              // like the phone app: level 1 by default
            reg.Popular[0].IsSelected = true;                        // a chip and its category row are the same item
            Assert.Contains(reg.Popular[0].Title, reg.SelectedTitles);
            Assert.Contains(reg.Categories, c => c.Options.Contains(reg.Popular[0]) && c.CountText.StartsWith("1 נבחרו", StringComparison.Ordinal));
        });
    }
}
