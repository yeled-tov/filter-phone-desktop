using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using FilterPhone.Core.Api;
using FilterPhone.Core.Ipc;
using FilterPhone.Core.Status;

namespace FilterPhone.App;

/// <summary>Base for small bindable items.</summary>
public abstract class Bindable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }
        field = value;
        Changed(name);
        return true;
    }
}

public sealed class LevelItem(CatalogLevel level) : Bindable
{
    private bool _selected;

    public int Level { get; } = level.Level;
    public string Title { get; } = $"רמה {level.Level} · {level.Name}";
    public string Name { get; } = level.Name;
    public string Summary { get; } = level.Summary;
    public string Description { get; } = level.Description;
    public bool HasDescription => Description.Length > 0;

    public bool IsSelected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }
}

public sealed class OptionItem(CatalogOption option) : Bindable
{
    private bool _selected;

    public string Id { get; } = option.Id;
    public string Category { get; } = option.Category;
    public string Title { get; } = option.Title;
    public string Description { get; } = option.Description;
    public string Warning { get; } = option.Warning.Length > 0 ? "⚠ " + option.Warning : string.Empty;
    public bool Popular { get; } = option.Popular;
    public bool HasDescription => Description.Length > 0;
    public bool HasWarning => Warning.Length > 0;

    /// <summary>Raised when the selection changes (the same item is shown both as a chip and in its category).</summary>
    public event EventHandler? SelectionChanged;

    public bool IsSelected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                SelectionChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }
}

public sealed class CategoryItem : Bindable
{
    private bool _expanded;

    public CategoryItem(CatalogCategory category, IReadOnlyList<OptionItem> options)
    {
        Title = category.Title;
        Description = category.Description;
        Options = options;
        foreach (var o in options)
        {
            o.SelectionChanged += (_, _) => Changed(nameof(CountText));
        }
    }

    public string Title { get; }
    public string Description { get; }
    public IReadOnlyList<OptionItem> Options { get; }

    public string CountText
    {
        get
        {
            var n = Options.Count(o => o.IsSelected);
            return n == 0 ? $"{Options.Count} אפשרויות" : $"{n} נבחרו מתוך {Options.Count}";
        }
    }

    public bool IsExpanded
    {
        get => _expanded;
        set => Set(ref _expanded, value);
    }
}

public sealed class StepItem(string title) : Bindable
{
    private bool _reached;
    private bool _current;

    public string Title { get; } = title;

    public bool IsReached
    {
        get => _reached;
        set => Set(ref _reached, value);
    }

    public bool IsCurrent
    {
        get => _current;
        set => Set(ref _current, value);
    }
}

/// <summary>Sends one command to the protection service (replaced in tests and previews).</summary>
public delegate Task<ServiceReply> ServiceSender(string command, JsonObject? args, TimeSpan timeout);

/// <summary>
/// The registration form, in the same four steps as the phone app: details → filtering level → what else to
/// block → summary and send. Only options a computer can enforce are offered. The request goes to the
/// administrator; nothing on this PC changes until it is approved.
/// </summary>
public sealed class RegistrationViewModel : Bindable
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };
    private readonly ServiceSender _send;
    private Catalog? _catalog;
    private int _step;
    private string _name = string.Empty;
    private string _phone = string.Empty;
    private string _email = string.Empty;
    private string _deviceName = string.Empty;
    private string _note = string.Empty;
    private string _error = string.Empty;
    private bool _busy;
    private bool _loading;
    private bool _catalogFailed;
    private int _prefillLevel = 1;
    private HashSet<string> _prefillOptions = [];

    public RegistrationViewModel(ServiceSender? send = null)
    {
        _send = send ?? ((c, a, t) => ServiceClient.SendAsync(c, a, t));
        NextCommand = new RelayCommand(NextAsync, () => !Busy && CatalogReady);
        BackCommand = new RelayCommand(() => { Back(); return Task.CompletedTask; }, () => !Busy);
        RetryCommand = new RelayCommand(LoadCatalogAsync, () => !Loading);
        EditDetailsCommand = new RelayCommand(() => { Step = 0; return Task.CompletedTask; });
        EditLevelCommand = new RelayCommand(() => { Step = 1; return Task.CompletedTask; });
        EditBlocksCommand = new RelayCommand(() => { Step = 2; return Task.CompletedTask; });
        Refresh();
    }

    /// <summary>Raised with the service's new snapshot when the request was sent.</summary>
    public event EventHandler<ProtectionSnapshot?>? Submitted;

    /// <summary>Raised when "back" is pressed on the first step.</summary>
    public event EventHandler? Left;

    public RelayCommand NextCommand { get; }
    public RelayCommand BackCommand { get; }
    public RelayCommand RetryCommand { get; }
    public RelayCommand EditDetailsCommand { get; }
    public RelayCommand EditLevelCommand { get; }
    public RelayCommand EditBlocksCommand { get; }

    public ObservableCollection<StepItem> Steps { get; } =
        [new("פרטים"), new("רמת סינון"), new("חסימות"), new("שליחה")];
    public ObservableCollection<LevelItem> Levels { get; } = [];
    public ObservableCollection<OptionItem> Popular { get; } = [];
    public ObservableCollection<CategoryItem> Categories { get; } = [];
    public ObservableCollection<string> SelectedTitles { get; } = [];

    public string Name { get => _name; set => Set(ref _name, value); }
    public string Phone { get => _phone; set => Set(ref _phone, value); }
    public string Email { get => _email; set => Set(ref _email, value); }
    public string DeviceName { get => _deviceName; set => Set(ref _deviceName, value); }
    public string Note { get => _note; set => Set(ref _note, value); }

    public int Step
    {
        get => _step;
        set
        {
            if (Set(ref _step, Math.Clamp(value, 0, Steps.Count - 1)))
            {
                Error = string.Empty;
                Refresh();
            }
        }
    }

    public bool IsDetails => Step == 0;
    public bool IsLevel => Step == 1 && CatalogReady;
    public bool IsBlocks => Step == 2 && CatalogReady;
    public bool IsSummary => Step == 3 && CatalogReady;
    public bool ShowCatalogWait => Step is 1 or 2 or 3 && !CatalogReady;
    public bool ShowPrevious => Step > 0;
    public string NextLabel => Step == Steps.Count - 1 ? "שליחת הבקשה" : "המשך";

    public bool CatalogReady => _catalog is not null;

    public bool Loading
    {
        get => _loading;
        private set { _loading = value; Changed(); Changed(nameof(CatalogWaitText)); RetryCommand.Raise(); }
    }

    public bool CatalogFailed
    {
        get => _catalogFailed;
        private set { _catalogFailed = value; Changed(); Changed(nameof(CatalogWaitText)); }
    }

    public string CatalogWaitText => CatalogFailed
        ? "לא ניתן היה לטעון את אפשרויות הסינון מהשרת. בדקו את החיבור לאינטרנט ונסו שוב."
        : "טוען את אפשרויות הסינון…";

    public bool Busy
    {
        get => _busy;
        private set { _busy = value; Changed(); NextCommand.Raise(); BackCommand.Raise(); }
    }

    public string Error
    {
        get => _error;
        private set { _error = value; Changed(); Changed(nameof(HasError)); }
    }

    public bool HasError => Error.Length > 0;

    public LevelItem? SelectedLevel => Levels.FirstOrDefault(l => l.IsSelected);
    public string LevelSummary => SelectedLevel is { } l ? $"{l.Title} — {l.Summary}" : "—";
    public bool HasNoBlocks => SelectedTitles.Count == 0;
    public bool HasEmail => Email.Trim().Length > 0;
    public bool HasNote => Note.Trim().Length > 0;
    public string DeviceNameShown => DeviceName.Trim().Length > 0 ? DeviceName.Trim() : "מחשב Windows";

    /// <summary>Fills the form again (after a refused request, "send a new request").</summary>
    public void Prefill(RegistrationInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        Name = info.Name;
        Phone = info.Phone;
        Email = info.Email;
        Note = info.Note;
        _prefillLevel = info.Level;
        _prefillOptions = [.. info.Options];
        if (_catalog is not null)
        {
            Apply(_catalog);
        }
        Step = 0;
    }

    public async Task LoadCatalogAsync()
    {
        if (Loading)
        {
            return;
        }
        Loading = true;
        CatalogFailed = false;
        try
        {
            var r = await _send(IpcProtocol.Commands.Catalog, null, TimeSpan.FromSeconds(30));
            var catalog = r.Ok && r.Data is not null ? r.Data.Deserialize<Catalog>(Options) : null;
            if (catalog is null || catalog.Levels.Count == 0)
            {
                CatalogFailed = true;
                return;
            }
            Apply(catalog);
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException
                                      or JsonException or TimeoutException)
        {
            CatalogFailed = true;
        }
        finally
        {
            Loading = false;
        }
    }

    /// <summary>Shows a catalog (also used directly by previews and tests).</summary>
    public void Apply(Catalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var selectedLevel = SelectedLevel?.Level ?? _prefillLevel;
        var selected = Categories.SelectMany(c => c.Options).Where(o => o.IsSelected).Select(o => o.Id).ToHashSet(StringComparer.Ordinal);
        selected.UnionWith(_prefillOptions);
        _prefillOptions = [];
        _catalog = catalog;

        Levels.Clear();
        foreach (var l in catalog.Levels.OrderBy(l => l.Level))
        {
            var item = new LevelItem(l) { IsSelected = l.Level == selectedLevel };
            item.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(LevelItem.IsSelected))
                {
                    Changed(nameof(SelectedLevel));
                    Changed(nameof(LevelSummary));
                }
            };
            Levels.Add(item);
        }
        if (SelectedLevel is null && Levels.Count > 0)
        {
            Levels[0].IsSelected = true;
        }

        var options = catalog.ForPc.Select(o => new OptionItem(o) { IsSelected = selected.Contains(o.Id) }).ToList();
        foreach (var o in options)
        {
            o.SelectionChanged += (_, _) => UpdateSelectedTitles();
        }
        Popular.Clear();
        foreach (var o in options.Where(o => o.Popular))
        {
            Popular.Add(o);
        }
        Categories.Clear();
        foreach (var c in catalog.Categories)
        {
            var inCategory = options.Where(o => o.Category == c.Id).ToList();
            if (inCategory.Count > 0)
            {
                Categories.Add(new CategoryItem(c, inCategory) { IsExpanded = inCategory.Any(o => o.IsSelected) });
            }
        }
        UpdateSelectedTitles();
        Refresh();
    }

    /// <summary>The titles of chosen options (for the summary and the waiting screen).</summary>
    public IReadOnlyList<string> TitlesOf(IEnumerable<string> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        var byId = _catalog?.Options.ToDictionary(o => o.Id, o => o.Title, StringComparer.Ordinal) ?? [];
        return ids.Select(id => byId.TryGetValue(id, out var t) ? t : id).ToList();
    }

    public string LevelName(int level) => _catalog?.Levels.FirstOrDefault(l => l.Level == level)?.Name ?? level.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private RegistrationForm Form() => new(Name.Trim(), Phone.Trim(), Email.Trim(), SelectedLevel?.Level ?? 0,
        Categories.SelectMany(c => c.Options).Where(o => o.IsSelected).Select(o => o.Id).Distinct(StringComparer.Ordinal).ToList(),
        Note.Trim(), DeviceName.Trim());

    private async Task NextAsync()
    {
        Error = string.Empty;
        if (Step == 0 && Form() is { } details && (details with { Level = 1 }).Problem() is { } problem)
        {
            Error = problem;
            return;
        }
        if (Step == 1 && SelectedLevel is null)
        {
            Error = "נא לבחור רמת סינון.";
            return;
        }
        if (Step < Steps.Count - 1)
        {
            Step++;
            return;
        }
        await SubmitAsync();
    }

    private void Back()
    {
        if (Step == 0)
        {
            Left?.Invoke(this, EventArgs.Empty);
            return;
        }
        Step--;
    }

    private async Task SubmitAsync()
    {
        var form = Form();
        if (form.Problem() is { } problem)
        {
            Error = problem;
            return;
        }
        Busy = true;
        try
        {
            var args = new JsonObject
            {
                ["name"] = form.Name,
                ["phone"] = form.Phone,
                ["email"] = form.Email,
                ["level"] = form.Level,
                ["options"] = new JsonArray([.. form.Options.Select(o => (JsonNode)o)]),
                ["note"] = form.Note,
                ["deviceName"] = form.DeviceName,
            };
            var r = await _send(IpcProtocol.Commands.Register, args, TimeSpan.FromMinutes(1));
            if (r.Ok)
            {
                Submitted?.Invoke(this, ServiceClient.ParseSnapshot(r.Data));
                return;
            }
            Error = Texts.RegisterError(r.Error, r.Message);
        }
        catch (Exception e) when (e is ServiceUnavailableException or IOException or OperationCanceledException or InvalidDataException
                                      or TimeoutException)
        {
            Error = Texts.ServiceDown;
        }
        finally
        {
            Busy = false;
        }
    }

    private void UpdateSelectedTitles()
    {
        SelectedTitles.Clear();
        foreach (var o in Categories.SelectMany(c => c.Options).Where(o => o.IsSelected))
        {
            SelectedTitles.Add(o.Title);
        }
        Changed(nameof(HasNoBlocks));
    }

    private void Refresh()
    {
        for (var i = 0; i < Steps.Count; i++)
        {
            Steps[i].IsReached = i <= Step;
            Steps[i].IsCurrent = i == Step;
        }
        foreach (var p in new[]
                 {
                     nameof(IsDetails), nameof(IsLevel), nameof(IsBlocks), nameof(IsSummary), nameof(ShowCatalogWait),
                     nameof(ShowPrevious), nameof(NextLabel), nameof(CatalogReady), nameof(LevelSummary), nameof(HasEmail),
                     nameof(HasNote), nameof(DeviceNameShown),
                 })
        {
            Changed(p);
        }
        NextCommand.Raise();
    }
}
