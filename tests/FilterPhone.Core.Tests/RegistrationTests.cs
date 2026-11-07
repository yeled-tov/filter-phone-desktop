using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using FilterPhone.Core.Api;
using FilterPhone.Core.Ipc;
using FilterPhone.Core.Status;
using FilterPhone.Core.Vpn;

namespace FilterPhone.Core.Tests;

public class RegistrationTests
{
    private static readonly Uri Base = new("https://api.filterphone.com");

    private const string CatalogJson = """
        {"levels": [{"level": 1, "name": "מחמיר", "short": "כל תמונה של אישה נחסמת", "desc": "..."},
                    {"level": 2, "name": "בינוני", "short": "לבוש צנוע עובר", "desc": "..."},
                    {"level": 9, "name": "לא קיים", "short": "", "desc": ""}],
         "categories": [{"id": "social", "title": "רשתות חברתיות", "desc": "פייסבוק, אינסטגרם..."},
                        {"id": "wa", "title": "וואטסאפ", "desc": ""}],
         "options": [{"id": "instagram", "category": "social", "title": "אינסטגרם", "desc": "", "popular": true, "warn": "", "pc": true},
                     {"id": "whatsapp_status", "category": "wa", "title": "סטטוסים", "desc": "", "popular": true, "warn": "", "pc": false},
                     {"id": "BAD ID", "category": "social", "title": "x", "desc": "", "popular": false, "warn": ""},
                     {"id": "orphan", "category": "nope", "title": "x", "desc": "", "popular": false, "warn": ""}]}
        """;

    private static RegistrationForm Form(string name = "משה כהן", string phone = "050-1234567", string email = "", int level = 1) =>
        new(name, phone, email, level, ["instagram"], "גם יוטיוב", "מחשב הבית");

    [Fact]
    public void Catalog_keeps_only_valid_entries_and_knows_what_applies_to_a_pc()
    {
        using var doc = JsonDocument.Parse(CatalogJson);
        var c = Catalog.Parse(doc.RootElement);
        Assert.Equal([1, 2], c.Levels.Select(l => l.Level));
        Assert.Equal("לבוש צנוע עובר", c.Levels[1].Summary);
        Assert.Equal(["instagram", "whatsapp_status"], c.Options.Select(o => o.Id));
        Assert.Equal(["instagram"], c.ForPc.Select(o => o.Id));

        // An older server does not say: everything is offered.
        using var old = JsonDocument.Parse(CatalogJson.Replace(", \"pc\": true", "", StringComparison.Ordinal)
            .Replace(", \"pc\": false", "", StringComparison.Ordinal));
        Assert.Equal(2, Catalog.Parse(old.RootElement).ForPc.Count());
        using var empty = JsonDocument.Parse("{\"levels\": []}");
        Assert.Throws<ApiException>(() => Catalog.Parse(empty.RootElement));
    }

    [Theory]
    [InlineData("מ", "050-1234567", "", 1, "נא למלא שם מלא.")]
    [InlineData("משה כהן", "0501", "", 1, "מספר הטלפון לא תקין.")]
    [InlineData("משה כהן", "050-123456a7", "", 1, "מספר הטלפון לא תקין.")]
    [InlineData("משה כהן", "050-1234567", "not-an-email", 1, "כתובת המייל לא תקינה.")]
    [InlineData("משה כהן", "050-1234567", "", 0, "נא לבחור רמת סינון.")]
    public void Form_problems_are_explained_in_hebrew(string name, string phone, string email, int level, string expected) =>
        Assert.Equal(expected, Form(name, phone, email, level).Problem());

    [Fact]
    public void A_complete_form_is_valid()
    {
        Assert.Null(Form().Problem());
        Assert.Null(Form(email: "moshe@example.co.il").Problem());
        Assert.Null(Form(phone: "+972 50 123 4567").Problem());
    }

    [Fact]
    public async Task Register_sends_the_form_as_a_windows_device_and_returns_the_pending_token()
    {
        var handler = new FakeHandler((_, _) => FakeHandler.Json(HttpStatusCode.Created,
            "{\"device_id\": 12, \"token\": \"" + new string('t', 43) + "\", \"status\": \"pending\", \"request_id\": 5, " +
            "\"message\": \"הבקשה התקבלה ומחכה לאישור.\"}"));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        using var keys = WireGuardKeys.Generate();
        var r = await client.RegisterAsync(Form(), keys.PublicKey, "0123456789abcdef", default);
        Assert.Equal((12, "pending", 5), (r.DeviceId, r.Status, r.RequestId));
        Assert.DoesNotContain(new string('t', 43), r.ToString(), StringComparison.Ordinal);
        var call = handler.Calls.Single();
        Assert.Equal("/v1/register", call.Request.RequestUri!.AbsolutePath);
        using var body = JsonDocument.Parse(call.Body!);
        var b = body.RootElement;
        Assert.Equal("windows", b.GetProperty("platform").GetString());
        Assert.Equal(1, b.GetProperty("level").GetInt32());
        Assert.Equal("instagram", b.GetProperty("options")[0].GetString());
        Assert.Equal(keys.PublicKey, b.GetProperty("public_key").GetString());
        Assert.Equal("מחשב הבית", b.GetProperty("device_name").GetString());
        Assert.False(b.TryGetProperty("private_key", out _));
        await Assert.ThrowsAsync<ArgumentException>(() => client.RegisterAsync(Form(phone: "1"), keys.PublicKey, "", default));
    }

    [Fact]
    public async Task Cancel_deletes_the_pending_device()
    {
        var handler = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.NoContent));
        using var client = new FilterPhoneApiClient(Base, handler: handler);
        await client.CancelRegistrationAsync("tok", default);
        Assert.Equal(HttpMethod.Delete, handler.Calls[0].Request.Method);
        Assert.Equal("/v1/device", handler.Calls[0].Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public void Waiting_and_refused_registrations_have_their_own_states()
    {
        var checks = Layers.All.ToDictionary(l => l, LayerCheck.Unknown);
        var now = DateTimeOffset.UtcNow;
        EvaluationContext Ctx(string? reg) => new(false, "pending", false, true, now) { Registration = reg };
        Assert.Equal(OverallState.AwaitingApproval, ProtectionEvaluator.Evaluate(checks, Ctx("pending")));
        Assert.Equal(OverallState.RegistrationRejected, ProtectionEvaluator.Evaluate(checks, Ctx("rejected")));
        Assert.Equal(OverallState.NotEnrolled, ProtectionEvaluator.Evaluate(checks, Ctx(null)));
    }

    [Fact]
    public void Ipc_registration_arguments_are_validated()
    {
        var args = new JsonObject
        {
            ["level"] = 2,
            ["options"] = new JsonArray("instagram", "youtube"),
            ["bad"] = new JsonArray("Instagram!"),
            ["many"] = new JsonArray([.. Enumerable.Range(0, 101).Select(i => (JsonNode)"a")]),
        };
        var id = new System.Text.RegularExpressions.Regex("^[a-z0-9_]{1,40}$");
        Assert.Equal(2, IpcProtocol.OptionalInt(args, "level", 1, 3));
        Assert.Null(IpcProtocol.OptionalInt(args, "missing", 1, 3));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalInt(new JsonObject { ["level"] = 7 }, "level", 1, 3));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalInt(new JsonObject { ["level"] = "2" }, "level", 1, 3));
        Assert.Equal(["instagram", "youtube"], IpcProtocol.OptionalStringArray(args, "options", 100, id));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalStringArray(args, "bad", 100, id));
        Assert.Throws<InvalidDataException>(() => IpcProtocol.OptionalStringArray(args, "many", 100, id));
        Assert.Empty(IpcProtocol.OptionalStringArray(args, "missing", 100, id));
        Assert.Matches(IpcProtocol.PersonTextPattern(), "שורה\nשורה שנייה");
        Assert.DoesNotMatch(IpcProtocol.PersonTextPattern(), "abc‮def");
        Assert.True(IpcProtocol.Commands.All.Contains(IpcProtocol.Commands.Register));
    }
}
