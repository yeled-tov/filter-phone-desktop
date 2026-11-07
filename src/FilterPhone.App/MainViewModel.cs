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

/// <summary>Which page the window shows.</summary>
public enum AppScreen
{
    Loading,
    Welcome,
    Register,
    Activation,
    Pending,
    Status,
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    // Status colours of the phone app (StatusColors) and its primary blue.
    private static readonly Brush Green = Brush("#1A7F37");
    private static readonly Brush Amber = Brush("#9C6500");
    private static readonly Brush Blue = Brush("#0B78BD");
    private static readonly Brush Red = Brush("#C62828");
    private static readonly Brush Gray = Brush("#5F6B7A");

    private AppScreen _localScreen = AppScreen.Welcome;
    private bool _gotSnapshot;

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
        StartRegisterCommand = new RelayCommand(StartRegisterAsync);
        StartActivationCommand = new RelayCommand(() => { Show(AppScreen.Activation); return Task.CompletedTask; });
        BackToWelcomeCommand = new RelayCommand(() => { Show(AppScreen.Welcome); return Task.CompletedTask; });
        CheckNowCommand = new RelayCommand(CheckNowAsync, () => !Busy);
        CancelRequestCommand = new RelayCommand(CancelRequestAsync, () => !Busy);
        NewRequestCommand = new RelayCommand(NewRequestAsync, () => !Busy);
        Registration = new RegistrationViewModel();
        Registration.Submitted += (_, snapshot) =>
        {
            Message = string.Empty;
            Apply(snapshot);
        };
        Registration.Left += (_, _) => Show(AppScreen.Welcome);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public RelayCommand ActivateCommand { get; }
    public RelayCommand VerifyCommand { get; }
    public RelayCommand ReconnectCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand WhatsAppCommand { get; }
    public RelayCommand EmailCommand { get; }
    public RelayCommand UpdateCommand { get; }
    public RelayCommand StartRegisterCommand { get; }
    public RelayCommand StartActivationCommand { get; }
    public RelayCommand BackToWelcomeCommand { get; }
    public RelayCommand CheckNowCommand { get; }
    public RelayCommand CancelRequestCommand { get; }
    public RelayCommand NewRequestCommand { get; }

    public RegistrationViewModel Registration { get; }

    public ObservableCollection<LayerRow> Rows { get; } = [];

    public bool IsEnrolled => _snapshot is { Overall: not (OverallState.NotEnrolled or OverallState.AwaitingApproval or OverallState.RegistrationRejected) };

    /// <summary>The page: the service decides once the PC is registered or activated; before that the user navigates.</summary>
    public AppScreen Screen => !_gotSnapshot ? AppScreen.Loading
        : _snapshot!.Overall is OverallState.AwaitingApproval or OverallState.RegistrationRejected ? AppScreen.Pending
        : IsEnrolled ? AppScreen.Status
        : _localScreen;

    public bool ShowLoading => _serviceReachable && Screen == AppScreen.Loading;
    public bool ShowWelcome => _serviceReachable && Screen == AppScreen.Welcome;
    public bool ShowRegister => _serviceReachable && Screen == AppScreen.Register;
    public bool ShowActivation => _serviceReachable && Screen == AppScreen.Activation;
    public bool ShowPending => _serviceReachable && Screen == AppScreen.Pending;
    public bool ShowStatus => _serviceReachable && Screen == AppScreen.Status;

    // ---- waiting for approval
    public bool IsRejected => _snapshot?.Overall == OverallState.RegistrationRejected;
    public bool IsWaiting => !IsRejected;
    public string PendingTitle => IsRejected ? "הבקשה לא אושרה" : "הבקשה נשלחה!";
    public string PendingMessage => _snapshot?.Registration?.Message is { Length: > 0 } m ? m
        : IsRejected ? "הבקשה לא אושרה. אפשר לשלוח בקשה חדשה." : "הבקשה התקבלה ומחכה לאישור. נעדכן ברגע שהחיבור ייפתח.";
    public string PendingWho => _snapshot?.Registration is { } r ? $"{r.Name} · {r.Phone}" : string.Empty;
    public string PendingLevel => _snapshot?.Registration is { Level: > 0 } r ? "רמת סינון: " + Registration.LevelName(r.Level) : string.Empty;
    public IReadOnlyList<string> PendingOptions => _snapshot?.Registration is { } r ? Registration.TitlesOf(r.Options) : [];
    public bool HasPendingOptions => PendingOptions.Count > 0;
    public string PendingNote => _snapshot?.Registration?.Note is { Length: > 0 } n ? "הערה: " + n : string.Empty;
    public bool HasPendingNote => PendingNote.Length > 0;
    public string PendingChecked => _snapshot?.Registration?.LastChecked is { } t
        ? "נבדק מול השרת: " + Texts.Ago(t) + ". התוכנה בודקת לבד כל חצי דקה — אפשר לסגור את החלון."
        : "התוכנה בודקת לבד כל חצי דקה — אפשר לסגור את החלון.";

    // ---- status hero
    public Geometry StateIcon => (Geometry)Application.Current.Resources[
        _snapshot?.Overall is OverallState.Protected or OverallState.ProtectedWithLimitations ? "IconShieldCheck" : "IconShieldAlert"];
    public Brush StateTint
    {
        get
        {
            var c = ((SolidColorBrush)StateColor).Color;
            var b = new SolidColorBrush(Color.FromArgb(0x1C, c.R, c.G, c.B));
            b.Freeze();
            return b;
        }
    }
    public string LevelLine => _snapshot?.LevelName is { Length: > 0 } l ? "רמת סינון: " + l : string.Empty;
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
            CheckNowCommand.Raise();
            CancelRequestCommand.Raise();
            NewRequestCommand.Raise();
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

    // The version is wrapped in left-to-right marks so "0.9.0-ci.12" is not reordered inside the Hebrew line.
    public string Version => "גרסה \u200E" + ProductConfig.Version + "\u200E";
    public string WindowsLine => _snapshot is null ? string.Empty : $"Windows {_snapshot.WindowsEdition} · build {_snapshot.WindowsBuild}";
    private string? _updateMessage;

    /// <summary>What the automatic updater is doing, from the service (with a transient message after "check now").</summary>
    public string UpdateState => _updateMessage ?? Texts.UpdateStatus(_snapshot?.Update ?? Core.Update.UpdateState.Unknown, _snapshot?.UpdateVersion);

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

    private void Show(AppScreen screen)
    {
        _localScreen = screen;
        Message = string.Empty;
        RaiseScreen();
    }

    private async Task StartRegisterAsync()
    {
        Show(AppScreen.Register);
        if (!Registration.CatalogReady)
        {
            await Registration.LoadCatalogAsync();
        }
    }

    private async Task CheckNowAsync()
    {
        Busy = true;
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.Verify, null, TimeSpan.FromMinutes(1));
            if (r.Ok)
            {
                Apply(ServiceClient.ParseSnapshot(r.Data));
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

    private async Task CancelRequestAsync()
    {
        if (MessageBox.Show("הבקשה תימחק, ותוכלו להירשם מחדש בכל עת.", "לבטל את הבקשה?", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No, MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign)
            != MessageBoxResult.Yes)
        {
            return;
        }
        await WithdrawAsync();
        Show(AppScreen.Welcome);
    }

    private async Task NewRequestAsync()
    {
        var previous = _snapshot?.Registration;
        await WithdrawAsync();
        if (previous is not null)
        {
            Registration.Prefill(previous);
        }
        await StartRegisterAsync();
    }

    private async Task WithdrawAsync()
    {
        Busy = true;
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.CancelRegistration, null, TimeSpan.FromSeconds(30));
            if (r.Ok)
            {
                Apply(ServiceClient.ParseSnapshot(r.Data));
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
        // The service checks and installs updates on its own; this just asks it to check right now.
        _updateMessage = "בודק עדכונים…";
        Changed(nameof(UpdateState));
        try
        {
            var r = await ServiceClient.SendAsync(IpcProtocol.Commands.CheckUpdate, null, TimeSpan.FromSeconds(30));
            if (r.Ok)
            {
                Apply(ServiceClient.ParseSnapshot(r.Data));
            }
            await Task.Delay(TimeSpan.FromSeconds(2));
            await RefreshAsync();
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException)
        {
            _updateMessage = Texts.ServiceDown;
        }
        finally
        {
            _updateMessage = null;
            Changed(nameof(UpdateState));
        }
    }

    // ------------------------------------------------------------------ helpers

    private void Apply(ProtectionSnapshot? s)
    {
        if (s is null)
        {
            return;
        }
        _snapshot = s;
        _gotSnapshot = true;
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
                     nameof(WindowsLine), nameof(ServerMessage), nameof(HasServerMessage), nameof(StateIcon), nameof(StateTint),
                     nameof(LevelLine), nameof(IsRejected), nameof(IsWaiting), nameof(PendingTitle), nameof(PendingMessage),
                     nameof(PendingWho), nameof(PendingLevel), nameof(PendingOptions), nameof(HasPendingOptions),
                     nameof(PendingNote), nameof(HasPendingNote), nameof(PendingChecked), nameof(UpdateState),
                 })
        {
            Changed(p);
        }
        RaiseScreen();
        if (s.Registration is not null && !Registration.CatalogReady && !Registration.Loading)
        {
            // Option titles for the "what you asked for" card.
            _ = Registration.LoadCatalogAsync().ContinueWith(_ => Application.Current?.Dispatcher.Invoke(() =>
            {
                Changed(nameof(PendingOptions));
                Changed(nameof(PendingLevel));
            }), TaskScheduler.Default);
        }
    }

    /// <summary>For previews and tests: show a snapshot without the service.</summary>
    internal void ApplyForPreview(ProtectionSnapshot snapshot) => Apply(snapshot);

    /// <summary>For previews and tests: open a page before activation.</summary>
    internal void ShowForPreview(AppScreen screen)
    {
        _gotSnapshot = true;
        _snapshot ??= new ProtectionSnapshot { Overall = OverallState.NotEnrolled, Checks = new Dictionary<string, LayerCheck>() };
        Show(screen);
    }

    private void RaiseScreen()
    {
        foreach (var p in new[]
                 {
                     nameof(Screen), nameof(ShowLoading), nameof(ShowWelcome), nameof(ShowRegister), nameof(ShowActivation),
                     nameof(ShowPending), nameof(ShowStatus),
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
        foreach (var p in new[] { nameof(ServiceUnreachable), nameof(ServiceProblem) })
        {
            Changed(p);
        }
        RaiseScreen();
    }

    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static SolidColorBrush Brush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
