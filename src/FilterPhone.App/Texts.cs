using FilterPhone.Core.Status;

namespace FilterPhone.App;

/// <summary>All user-facing Hebrew text. Technical codes never reach the user without a sentence.</summary>
public static class Texts
{
    public static string StateTitle(OverallState s) => Core.Support.StateText.Hebrew(s);

    public static string StateExplanation(OverallState s) => s switch
    {
        OverallState.Protected =>
            "החיבור לשרת הסינון, חסימת הגלישה מחוץ לסינון, תעודת הסינון, מסלול סינון התמונות, הגבלת הדפדפנים וחסימת החנות נבדקו ועברו.",
        OverallState.ProtectedWithLimitations =>
            "הסינון ברשת פעיל ונבדק. במחשב הזה חלק מהחסימות לא נעשות מראש, אלא בסגירה מיידית של מה שנפתח. פרטים בהמשך.",
        OverallState.Connecting => "מתחבר לשרת הסינון ובודק כל שכבת הגנה. זה לוקח בדרך כלל פחות מדקה.",
        OverallState.Reconnecting => "החיבור לשרת הסינון נותק ומתחבר מחדש. בינתיים הגלישה חסומה כדי שלא תעבור בלי סינון.",
        OverallState.ServerUnavailable => "שרת הסינון לא זמין כרגע. הגלישה חסומה עד שהחיבור יחזור. ננסה שוב אוטומטית.",
        OverallState.FilteringTestFailed => "בדיקת הסינון נכשלה: התעבורה לא עוברת דרך מסנן התמונות כמו שצריך. פנו לתמיכה.",
        OverallState.SetupIncomplete => "ההתקנה עדיין לא הושלמה, ולכן המחשב עדיין לא מוגן.",
        OverallState.AdminActionRequired => "נדרשת פעולה של מנהל המחשב. פרטים ברשימה למטה.",
        OverallState.DeviceInactive => "המכשיר לא פעיל בשרת (ממתין לאישור, הושבת או הוסר). פנו לתמיכה.",
        OverallState.NotEnrolled => "כדי להתחיל, הצטרפו לשירות או הזינו קוד הפעלה שקיבלתם מ-FilterPhone.",
        OverallState.AwaitingApproval => "הבקשה התקבלה ומחכה לאישור. אחרי האישור המחשב מתחבר לבד.",
        OverallState.RegistrationRejected => "הבקשה לא אושרה. אפשר לשלוח בקשה חדשה.",
        _ => string.Empty,
    };

    public static string LayerName(string layer) => layer switch
    {
        Layers.Enrollment => "הפעלת המכשיר",
        Layers.Tunnel => "חיבור מאובטח לשרת הסינון (VPN)",
        Layers.ServerPath => "השרת מאשר שהתעבורה עוברת דרכו",
        Layers.KillSwitch => "חסימת גלישה מחוץ לסינון",
        Layers.CaTrust => "תעודת הסינון",
        Layers.Interception => "סינון אתרים מאובטחים (HTTPS)",
        Layers.ImagePath => "מסלול סינון התמונות",
        Layers.ChromeOnly => "גלישה ב-Google Chrome בלבד",
        Layers.ChromePolicy => "הגדרות Chrome",
        Layers.StoreBlock => "חסימת חנות Microsoft",
        _ => layer,
    };

    public static string StateWord(CheckState s) => s switch
    {
        CheckState.Ok => "תקין",
        CheckState.Pending => "בבדיקה",
        CheckState.Failed => "לא תקין",
        CheckState.Unsupported => "לא נתמך במחשב זה",
        _ => "טרם נבדק",
    };

    public static string CodeExplanation(string code) => code switch
    {
        "enrolled" or "handshake" or "via_vpn" or "installed" or "trusted" or "intercepted" or "applied" or "enforced"
            or "image_through_filter" or "filter_acted" => string.Empty,
        "intercepted_partial" => "חלק מהאתרים לא נבדקו בסבב האחרון.",
        "unauthorized" => "השרת לא מזהה את המכשיר. פנו לתמיכה.",
        "secrets_missing" => "נתוני ההפעלה חסרים. הפעילו מחדש עם קוד הפעלה.",
        "wireguard_missing" => "רכיב ה-VPN (WireGuard) לא מותקן. הריצו שוב את תוכנת ההתקנה.",
        "wireguard_not_trusted" => "רכיב ה-VPN לא עבר בדיקת חתימה. הריצו שוב את תוכנת ההתקנה.",
        "consent_missing" => "חסר אישור מנהל מתוכנת ההתקנה. הריצו שוב את ההתקנה.",
        "waiting_for_verified_tunnel" => "תופעל אוטומטית מיד כשהחיבור לשרת יאומת.",
        "key_missing" => "מפתח החיבור חסר — מחדשים אותו מול השרת.",
        "not_installed" or "install_failed" => "שירות החיבור לא הותקן. מנסה שוב.",
        "stopped" => "שירות החיבור נעצר — מופעל מחדש.",
        "no_handshake" or "stale_handshake" => "אין כרגע תקשורת עם שרת הסינון. מנסה שוב.",
        "start_failed" or "start_timeout" or "query_failed" => "שירות החיבור לא עלה. מנסה שוב.",
        "endpoint_unresolved" => "לא נמצאה כתובת שרת הסינון.",
        "api_unreachable" => "שרת FilterPhone לא עונה כרגע.",
        "not_via_vpn" => "השרת לא רואה את התעבורה דרך החיבור המאובטח.",
        "no_traffic" => "החיבור קיים אבל לא עוברת בו תעבורה.",
        "tunnel_down" => "ממתין לחיבור.",
        "ca_missing" or "ca_invalid" => "תעודת הסינון חסרה או לא תקינה. פנו לתמיכה.",
        "store_error" => "לא ניתן היה להתקין את תעודת הסינון.",
        "not_intercepted" => "אתרים מאובטחים לא עוברים דרך הסינון.",
        "ca_not_trusted" => "תעודת הסינון לא מותקנת כראוי במחשב.",
        "image_not_through_filter" => "תמונות לא עוברות דרך מסנן התמונות.",
        "unreachable" or "no_response" => "לא ניתן היה להגיע לאתר הבדיקה.",
        "no_ca" => "חסרה תעודת הסינון לבדיקה.",
        "edition_unsupported" => "ב-Windows Home אין חסימה מראש של דפדפנים אחרים, אבל כל דפדפן אחר שייפתח נסגר מיד. הסינון ברשת פעיל במלואו.",
        "not_enforced_on_this_windows" => "Windows לא חסם מראש דפדפנים במחשב זה, אבל כל דפדפן אחר שייפתח נסגר מיד. הסינון ברשת פעיל.",
        "chrome_missing" => "Google Chrome לא מותקן. מנהל המחשב צריך להתקין את Chrome.",
        "chrome_blocked" => "Chrome עצמו נחסם — פנו לתמיכה.",
        "foreign_applocker_policy" => "במחשב יש כבר מדיניות AppLocker של הארגון. נדרש מנהל מערכת.",
        "applocker_apply_failed" or "error" => "החלת חסימת הדפדפנים נכשלה. מנסה שוב מאוחר יותר.",
        "no_user_session" => "ממתין למשתמש מחובר כדי לבדוק.",
        "not_applied" or "applied_csp" => "מחיל ובודק את ההגדרה.",
        "not_checked" => string.Empty,
        "not_requested" => "לא הופעל — לפי הבחירה בזמן ההתקנה.",
        "disabled_by_admin" => "כובה על ידי מנהל FilterPhone.",
        "store_not_installed" => "חנות Microsoft לא מותקנת במחשב הזה.",
        "store_closed_on_open" => "ב-Windows הזה החנות לא נחסמת מראש, אבל אם היא נפתחת היא נסגרת מיד.",
        "store_not_blocked" => "החנות עדיין לא חסומה. מנסה שוב.",
        "store_check_failed" => "בדיקת חסימת החנות לא הושלמה. מנסה שוב.",
        _ when code.StartsWith("wfp_", StringComparison.Ordinal) => "התקנת חסימת הגלישה נכשלה. פנו לתמיכה.",
        _ when code.StartsWith("http_", StringComparison.Ordinal) => "אתר הבדיקה החזיר תשובה לא צפויה.",
        _ => string.Empty,
    };

    public static string EnrollError(string? code, string? serverMessage) => code switch
    {
        "invalid_code" => serverMessage ?? "קוד ההפעלה לא תקין או שפג תוקפו.",
        "rate_limited" => "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות.",
        "network" => "אין חיבור לשרת FilterPhone. בדקו את החיבור לאינטרנט ונסו שוב.",
        "wireguard_missing" => "רכיב ה-VPN לא מותקן. הריצו שוב את תוכנת ההתקנה.",
        "already_enrolled" => "המחשב כבר מופעל.",
        "ca_invalid" => "תעודת הסינון שהתקבלה מהשרת לא עברה בדיקה. ההפעלה בוטלה. פנו לתמיכה.",
        "conflict" => "המכשיר כבר רשום. נסו שוב.",
        "bad_request" => "הנתונים שהוזנו לא תקינים.",
        _ => serverMessage ?? "ההפעלה לא הושלמה. נסו שוב או פנו לתמיכה.",
    };

    public static string UpdateStatus(Core.Update.UpdateState state, string? version) => state switch
    {
        Core.Update.UpdateState.UpToDate => "מותקנת הגרסה העדכנית. FilterPhone בודק עדכונים לבד ומתקין אותם ברקע.",
        Core.Update.UpdateState.Checking => "בודק אם יש עדכון…",
        Core.Update.UpdateState.Downloading => version is { Length: > 0 } v ? $"מוריד את גרסה {v} ברקע…" : "מוריד עדכון ברקע…",
        Core.Update.UpdateState.Installing => version is { Length: > 0 } v ? $"מתקין את גרסה {v} — המחשב יתעדכן לבד, בלי לשים לב." : "מתקין עדכון ברקע…",
        Core.Update.UpdateState.Available => version is { Length: > 0 } v
            ? $"יש גרסה חדשה ({v}). בגרסה הזו ההתקנה האוטומטית כבויה (הקובץ לא חתום) — הורידו אותה מדף ההורדות."
            : "יש גרסה חדשה. הורידו אותה מדף ההורדות.",
        Core.Update.UpdateState.Error => "בדיקת העדכונים לא הצליחה כרגע. ננסה שוב אוטומטית.",
        Core.Update.UpdateState.Disabled => "בדיקת עדכונים אוטומטית לא הוגדרה בגרסה זו.",
        _ => "בודק עדכונים אוטומטית ברקע.",
    };

    public static string RegisterError(string? code, string? serverMessage) => code switch
    {
        "bad_request" => serverMessage ?? "חלק מהפרטים לא תקינים. בדקו ונסו שוב.",
        "rate_limited" => "נשלחו כמה בקשות ברצף. נסו שוב בעוד כמה דקות.",
        "registration_closed" => serverMessage ?? "ההרשמה סגורה כרגע. פנו אלינו לקבלת קוד הפעלה.",
        "already_registered" => "כבר נשלחה בקשה מהמחשב הזה. היא מחכה לאישור.",
        "already_enrolled" => "המחשב כבר מופעל.",
        "conflict" => "המחשב כבר רשום. נסו שוב.",
        "wireguard_missing" => "רכיב ה-VPN לא מותקן. הריצו שוב את תוכנת ההתקנה.",
        "network" => "אין חיבור לשרת FilterPhone. בדקו את החיבור לאינטרנט ונסו שוב.",
        _ => serverMessage ?? "השליחה לא הצליחה. נסו שוב בעוד כמה דקות.",
    };

    public const string ServiceDown =
        "שירות ההגנה של FilterPhone לא עונה. אם זה נמשך, הפעילו מחדש את המחשב או התקינו מחדש.";

    public const string ServiceNotTrusted =
        "התוכנה שעונה במקום שירות ההגנה אינה של FilterPhone. פנו לתמיכה.";

    public static string Ago(DateTimeOffset? t)
    {
        if (t is null)
        {
            return "עדיין לא";
        }
        var age = DateTimeOffset.UtcNow - t.Value;
        if (age.TotalSeconds < 60)
        {
            return "לפני פחות מדקה";
        }
        if (age.TotalMinutes < 60)
        {
            return $"לפני {(int)age.TotalMinutes} דקות";
        }
        return t.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm", System.Globalization.CultureInfo.GetCultureInfo("he-IL"));
    }
}
