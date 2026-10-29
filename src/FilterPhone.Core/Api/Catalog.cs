using System.Text.Json;
using System.Text.Json.Serialization;

namespace FilterPhone.Core.Api;

/// <summary>A filtering level offered at registration (server: catalog.LEVELS).</summary>
public sealed record CatalogLevel(int Level, string Name, string Summary, string Description);

/// <summary>A group of blocking options (server: catalog.CATEGORIES).</summary>
public sealed record CatalogCategory(string Id, string Title, string Description);

/// <summary>
/// One blocking option (server: catalog.Option.public). <see cref="AppliesToPc"/> is false only when the
/// server says the option is enforced on the phone alone; null when an older server does not say.
/// </summary>
public sealed record CatalogOption(string Id, string Category, string Title, string Description, bool Popular, string Warning,
    bool? AppliesToPc);

/// <summary><c>GET /v1/catalog</c>: what a new customer can choose in the registration form.</summary>
public sealed record Catalog(IReadOnlyList<CatalogLevel> Levels, IReadOnlyList<CatalogCategory> Categories,
    IReadOnlyList<CatalogOption> Options)
{
    /// <summary>The options a computer can enforce (all of them, if the server does not say).</summary>
    [JsonIgnore]
    public IEnumerable<CatalogOption> ForPc => Options.Where(o => o.AppliesToPc != false);

    public static Catalog Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new ApiException(ApiErrorKind.InvalidResponse, 200, null);
        }
        var levels = Items(root, "levels")
            .Select(e => new CatalogLevel(Json.Int(e, "level"), Json.String(e, "name"), Json.String(e, "short"), Json.String(e, "desc")))
            .Where(l => l.Level is >= 1 and <= 3 && l.Name.Length > 0)
            .ToList();
        var categories = Items(root, "categories")
            .Select(e => new CatalogCategory(Json.String(e, "id"), Json.String(e, "title"), Json.String(e, "desc")))
            .Where(c => c.Id.Length > 0 && c.Title.Length > 0)
            .ToList();
        var known = categories.Select(c => c.Id).ToHashSet(StringComparer.Ordinal);
        var options = Items(root, "options")
            .Select(e => new CatalogOption(Json.String(e, "id"), Json.String(e, "category"), Json.String(e, "title"),
                Json.String(e, "desc"), Json.Bool(e, "popular") ?? false, Json.String(e, "warn"), Json.Bool(e, "pc")))
            .Where(o => IsOptionId(o.Id) && o.Title.Length > 0 && known.Contains(o.Category))
            .ToList();
        if (levels.Count == 0)
        {
            throw new ApiException(ApiErrorKind.InvalidResponse, 200, null);
        }
        return new Catalog(levels, categories, options);
    }

    /// <summary>Option ids are short lowercase identifiers (e.g. "whatsapp_status").</summary>
    public static bool IsOptionId(string id) =>
        id.Length is > 0 and <= 40 && id.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_');

    private static IEnumerable<JsonElement> Items(JsonElement root, string name) =>
        root.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object)
            : [];
}

/// <summary>What the customer fills in the registration form (server: RegisterIn).</summary>
public sealed record RegistrationForm(string Name, string Phone, string Email, int Level, IReadOnlyList<string> Options,
    string Note, string DeviceName)
{
    /// <summary>Hebrew reason the form cannot be sent, or null when it is valid (same rules as the server).</summary>
    public string? Problem()
    {
        if (Name.Trim().Length < 2)
        {
            return "נא למלא שם מלא.";
        }
        if (Phone.Count(char.IsAsciiDigit) < 9 || Phone.Any(c => !(char.IsAsciiDigit(c) || c is '+' or '-' or ' ')))
        {
            return "מספר הטלפון לא תקין.";
        }
        var email = Email.Trim();
        if (email.Length > 0 && !IsEmail(email))
        {
            return "כתובת המייל לא תקינה.";
        }
        if (Level is < 1 or > 3)
        {
            return "נא לבחור רמת סינון.";
        }
        return Options.All(Catalog.IsOptionId) ? null : "אחת מאפשרויות החסימה לא תקינה.";
    }

    private static bool IsEmail(string s)
    {
        var at = s.IndexOf('@', StringComparison.Ordinal);
        var dot = s.LastIndexOf('.');
        return at > 0 && at == s.LastIndexOf('@') && dot > at + 1 && dot < s.Length - 2 && !s.Any(char.IsWhiteSpace);
    }
}

/// <summary><c>POST /v1/register</c>: the device exists on the server as "pending" until the administrator approves it.</summary>
public sealed record RegistrationResult(int DeviceId, string Token, string Status, int RequestId, string Message)
{
    public override string ToString() => $"RegistrationResult(device={DeviceId}, request={RequestId}, status={Status}, token=<redacted>)";
}
