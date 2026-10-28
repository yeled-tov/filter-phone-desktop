using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using FilterPhone.Core;
using FilterPhone.Core.Ipc;
using FilterPhone.Core.Status;
using FilterPhone.Core.Support;

namespace FilterPhone.App;

public sealed class LayerRow(string name, string state, string detail, Brush color)
{
    public string Name { get; } = name;
    public string State { get; } = state;
    public string Detail { get; } = detail;
    public Brush Color { get; } = color;
    public bool HasDetail => Detail.Length > 0;
    public string Accessible => $"{Name}: {State}. {Detail}";
}

public sealed class RelayCommand(Func<Task> run, Func<bool>? can = null) : ICommand
{
    private bool _running;

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => !_running && (can?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        _running = true;
        Raise();
        try
        {
            await run();
        }
        finally
        {
            _running = false;
            Raise();
        }
    }

    public void Raise() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private static readonly Brush Green = Brush("#1B7F3B");
    private static readonly Brush Amber = Brush("#8A5A00");
    private static readonly Brush Blue = Brush("#1E5AA8");
    private static readonly Brush Red = Brush("#B3261E");
    private static readonly Brush Gray = Brush("#5F6B7A");

    private ProtectionSnapshot? _snapshot;
    private string _code = string.Empty;
    private string _deviceName = string.Empty;
    private string _message = string.Empty;
    private string _supportMessage = string.Empty;
    private bool _attachReport;
    private bool _busy;
    private bool _serviceReachable = true;
    private bool _supportEdited;

    public MainViewModel()
    {
        ActivateCommand = new RelayCommand(ActivateAsync, () => !Busy && Code.Trim().Length >= 6);
        VerifyCommand = new RelayCommand(VerifyAsync, () => !Busy);
        ReconnectCommand = new RelayCommand(ReconnectAsync, () => !Busy);
        ExportCommand = new RelayCommand(ExportAsync, () => !Busy);
        WhatsAppCommand = new RelayCommand(OpenSupportAsync);
        EmailCommand = new RelayCommand(OpenEmailAsync, () => EmailConfigured);
        UpdateCommand = new RelayCommand(CheckUpdateAsync);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public RelayCommand ActivateCommand { get; }
    public RelayCommand VerifyCommand { get; }
    public RelayCommand ReconnectCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand WhatsAppCommand { get; }
    public RelayCommand EmailCommand { get; }
    public RelayCommand UpdateCommand { get; }

    public ObservableCollection<LayerRow> Rows { get; } = [];

    public bool IsEnrolled => _snapshot is { Overall: not OverallState.NotEnrolled };
    public bool ShowActivation => _serviceReachable && !IsEnrolled;
    public bool ShowStatus => _serviceReachable && IsEnrolled;
    public bool ServiceUnreachable => !_serviceReachable;
    public string ServiceProblem { get; private set; } = Texts.ServiceDown;

    public string StateTitle => _snapshot is null ? "מתחבר לשירות ההגנה…" : Texts.StateTitle(_snapshot.Overall);
    public string StateExplanation => _snapshot is null ? string.Empty : Texts.StateExplanation(_snapshot.Overall);
    public string ServerMessage => _snapshot?.ServerMessage ?? string.Empty;
    public bool HasServerMessage => ServerMessage.Length > 0 && _snapshot?.Overall == OverallState.DeviceInactive;
    public Brush StateColor => _snapshot?.Overall switch
    {
        OverallState.Protected => Green,
        OverallState.ProtectedWithLimitations => Amber,
        OverallState.Connecting or OverallState.Reconnecting => Blue,
        OverallState.NotEnrolled or null => Gray,
        _ => Red,
    };
    public string LastVerified => "בדיקה מלאה אחרונה שעברה: " + Texts.Ago(_snapshot?.LastVerified);
    public string DeviceLine => _snapshot?.DeviceId is int id
        ? $"מכשיר #{id}" + (_snapshot.LevelName is { Length: > 0 } l ? $" · רמת סינון: {l}" : string.Empty)
        : string.Empty;

    public string Code
    {
        get => _code;
        set { _code = value; Changed(); ActivateCommand.Raise(); }
    }

    public string DeviceName
    {
        get => _deviceName;
        set { _deviceName = value; Changed(); }
    }

    public string Message
    {
        get => _message;
        private set { _message = value; Changed(); Changed(nameof(HasMessage)); }
    }

    public bool HasMessage => Message.Length > 0;

    public bool Busy
    {
        get => _busy;
        private set
        {
            _busy = value;
            Changed();
            ActivateCommand.Raise();
            VerifyCommand.Raise();
            ReconnectCommand.Raise();
            ExportCommand.Raise();
        }
    }

    public string SupportMessage
    {
        get => _supportMessage;
        set { _supportMessage = value; _supportEdited = true; Changed(); }
    }

    public bool AttachReport
    {
        get => _attachReport;
        set { _attachReport = value; Changed(); }
    }

    public string SupportNumber => SupportLauncher.Number(_snapshot?.SupportWhatsApp ?? string.Empty);
    public string SupportNumberDisplay => SupportNumber.StartsWith("972", StringComparison.Ordinal) ? "0" + SupportNumber[3..] : SupportNumber;
    public bool EmailConfigured => ProductConfig.Current.SupportEmail.Length > 0;
    public string EmailNote => EmailConfigured
        ? "אם WhatsApp לא מותקן במחשב, תיפתח הודעת מייל מוכנה לתמיכה."
        : "כתובת מייל לתמיכה לא הוגדרה בגרסה זו. אם WhatsApp לא מותקן, ייפתח WhatsApp באתר דרך Chrome.";
    public string WhatsAppState => SupportLauncher.WhatsAppDesktopInstalled()
        ? "WhatsApp מותקן במחשב — ההודעה תיפתח בו."
        : "WhatsApp לא מותקן במחשב.";

    public string Version => "גרסה " + ProductConfig.Version;
    public string WindowsLine => _snapshot is null ? string.Empty : $"Windows {_snapshot.WindowsEdition} · build {_snapshot.WindowsBuild}";
    public string UpdateState { get; private set; } = Updater.Configured ? string.Empty : "בדיקת עדכונים אוטומטית לא הוגדרה בגרסה זו. עדכון נעשה בהרצת תוכנת ההתקנה החדשה.";

    // ------------------------------------------------------------------ actions

    public async Task RefreshAsync()
    {
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Status, null, TimeSpan.FromSeconds(10));
            if (r.Ok)
            {
                Apply(ServiceClient.ParseSnapshot(r.Data));
            }
            SetReachable(true, Texts.ServiceDown);
        }
        catch (ServiceUnavailableException e)
        {
            SetReachable(false, e.Message == "server_not_trusted" ? Texts.ServiceNotTrusted : Texts.ServiceDown);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            SetReachable(false, Texts.ServiceDown);
        }
    }

    private async Task ActivateAsync()
    {
        Busy = true;
        Message = "מפעיל… (עד דקה)";
        try
        {
            var args = new JsonObject { ["code"] = Code.Trim(), ["deviceName"] = DeviceName.Trim() };
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Enroll, args, TimeSpan.FromMinutes(2));
            if (r.Ok)
            {
                Code = string.Empty;
                Message = "ההפעלה הצליחה. מתחבר לשרת הסינון ובודק את ההגנה…";
                Apply(ServiceClient.ParseSnapshot(r.Data));
            }
            else
            {
                Message = Texts.EnrollError(r.Error, r.Message);
            }
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
            Message = Texts.ServiceDown;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task VerifyAsync()
    {
        Busy = true;
        Message = "בודק את כל שכבות ההגנה…";
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Verify, null, TimeSpan.FromMinutes(2));
            if (r.Ok)
            {
                Apply(ServiceClient.ParseSnapshot(r.Data));
                Message = _snapshot?.Overall == OverallState.Protected
                    ? "הבדיקה הסתיימה: כל שכבות ההגנה תקינות, כולל מסלול סינון התמונות."
                    : "הבדיקה הסתיימה. ראו בפירוט למטה מה עוד לא תקין.";
            }
            else
            {
                Message = r.Error == IpcProtocol.Errors.RateLimited ? "בדיקה כבר רצה לאחרונה. נסו שוב בעוד דקה." : "הבדיקה לא הושלמה.";
            }
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
            Message = Texts.ServiceDown;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task ReconnectAsync()
    {
        Busy = true;
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Reconnect, null, TimeSpan.FromSeconds(90));
            Message = r.Ok ? "מתחבר מחדש…" : "אפשר לנסות שוב בעוד דקה.";
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
            Message = Texts.ServiceDown;
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task<string?> DiagnosticsAsync()
    {
        var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Diagnostics, null, TimeSpan.FromSeconds(20));
        return r.Ok ? r.Data?["report"]?.GetValue<string>() : null;
    }

    private async Task ExportAsync()
    {
        try
        {
            var report = await DiagnosticsAsync();
            if (report is null)
            {
                Message = "לא ניתן היה להפיק דוח אבחון.";
                return;
            }
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                FileName = $"FilterPhone-diagnostics-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                Filter = "קובץ טקסט|*.txt",
            };
            if (dialog.ShowDialog() == true)
            {
                await File.WriteAllTextAsync(dialog.FileName, report, System.Text.Encoding.UTF8);
                Message = "דוח האבחון נשמר. הוא לא כולל קוד הפעלה, מפתחות, הגדרות VPN או היסטוריית גלישה.";
            }
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException
                                      or UnauthorizedAccessException)
        {
            Message = "לא ניתן היה לשמור את דוח האבחון.";
        }
    }

    private async Task PrepareAttachmentAsync()
    {
        if (!AttachReport)
        {
            return;
        }
        var report = await DiagnosticsAsync();
        if (report is not null)
        {
            var path = SupportLauncher.SaveReportForAttachment(report);
            Message = $"דוח האבחון נשמר ב-{path}. אפשר לגרור אותו לשיחה או למייל.";
        }
    }

    private async Task OpenSupportAsync()
    {
        try
        {
            await PrepareAttachmentAsync();
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
        }
        var channel = SupportLauncher.Open(SupportNumber, SupportMessage, ProductConfig.Current.SupportEmail);
        if (!AttachReport)
        {
            Message = channel switch
            {
                SupportLauncher.Channel.WhatsAppDesktop => "WhatsApp נפתח עם ההודעה. אפשר לערוך אותה ולשלוח.",
                SupportLauncher.Channel.Email => "נפתחה הודעת מייל מוכנה. אפשר לערוך אותה ולשלוח.",
                SupportLauncher.Channel.WhatsAppWeb => "WhatsApp נפתח בדפדפן עם ההודעה.",
                _ => $"לא ניתן היה לפתוח WhatsApp או מייל. אפשר לפנות בוואטסאפ למספר {SupportNumberDisplay}.",
            };
        }
    }

    private async Task OpenEmailAsync()
    {
        try
        {
            await PrepareAttachmentAsync();
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
        }
        if (!SupportLauncher.OpenEmail(ProductConfig.Current.SupportEmail, SupportMessage))
        {
            Message = "לא נמצאה תוכנת דואר במחשב.";
        }
    }

    private async Task CheckUpdateAsync()
    {
        if (!Updater.Configured)
        {
            return;
        }
        try
        {
            UpdateState = "בודק עדכונים…";
            Changed(nameof(UpdateState));
            var update = await Updater.CheckAsync(CancellationToken.None);
            if (update is null)
            {
                UpdateState = "מותקנת הגרסה העדכנית.";
            }
            else if (MessageBox.Show($"קיימת גרסה חדשה ({update.Version}). להוריד ולהתקין? Windows יבקש אישור מנהל.",
                         "עדכון FilterPhone", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No,
                         MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign) == MessageBoxResult.Yes)
            {
                UpdateState = await Updater.DownloadVerifyAndStartAsync(update, CancellationToken.None)
                    ? "תוכנת ההתקנה של הגרסה החדשה נפתחה."
                    : "העדכון לא עבר את בדיקת החתימה או התקינות ולכן לא הותקן.";
            }
        }
        catch (Exception e) when (e is System.Net.Http.HttpRequestException or IOException or OperationCanceledException
                                      or System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException)
        {
            UpdateState = "בדיקת העדכונים נכשלה. נסו שוב מאוחר יותר.";
        }
        Changed(nameof(UpdateState));
    }

    // ------------------------------------------------------------------ helpers

    private void Apply(ProtectionSnapshot? s)
    {
        if (s is null)
        {
            return;
        }
        _snapshot = s;
        Rows.Clear();
        foreach (var layer in Layers.All)
        {
            if (!s.Checks.TryGetValue(layer, out var c))
            {
                continue;
            }
            var color = c.State switch
            {
                CheckState.Ok => Green,
                CheckState.Unsupported => Amber,
                CheckState.Failed => Red,
                CheckState.Pending => Blue,
                _ => Gray,
            };
            Rows.Add(new LayerRow(Texts.LayerName(layer), Texts.StateWord(c.State), Texts.CodeExplanation(c.Code), color));
        }
        if (!_supportEdited)
        {
            _supportMessage = Core.Support.SupportMessage.Compose(s);
            Changed(nameof(SupportMessage));
        }
        foreach (var p in new[]
                 {
                     nameof(IsEnrolled), nameof(ShowActivation), nameof(ShowStatus), nameof(StateTitle), nameof(StateExplanation),
                     nameof(StateColor), nameof(LastVerified), nameof(DeviceLine), nameof(SupportNumber), nameof(SupportNumberDisplay),
                     nameof(WindowsLine), nameof(ServerMessage), nameof(HasServerMessage),
                 })
        {
            Changed(p);
        }
    }

    private void SetReachable(bool reachable, string problem)
    {
        if (_serviceReachable == reachable && ServiceProblem == problem)
        {
            return;
        }
        _serviceReachable = reachable;
        ServiceProblem = problem;
        foreach (var p in new[] { nameof(ShowActivation), nameof(ShowStatus), nameof(ServiceUnreachable), nameof(ServiceProblem) })
        {
            Changed(p);
        }
    }

    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static SolidColorBrush Brush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
