# שילוב ה-API — FilterPhone Desktop

כל הנתיבים, הסכמות וכללי האימות אומתו ישירות מקוד השרת ב-`yeled-tov/filterphone`
(`server/filterphone/api/app.py`, `service.py`, `security.py`) ומבדיקות השרת,
לא מהנחות. הלקוח הוא `FilterPhone.Core/Api/FilterPhoneApiClient`.

- **בסיס**: `https://api.filterphone.com` (מ-`app/lib/src/config.dart` ומ-
  `settings.py: public_host`). ניתן לדריסה בבנייה: `FpApiBaseUrl`.
- **אימות מכשיר**: `Authorization: Bearer <device token>`.
- **פלטפורמה**: `platform=windows` (השרת מקבל כל מחרוזת ≤20 ושומר אותה כפי שהיא).

## נתיבים שהלקוח משתמש בהם

| נתיב | שיטה | שימוש | שדות שנשלחים |
|---|---|---|---|
| `/v1/enroll` | POST | הפעלה בקוד | `code`, `public_key`, `name`, `platform`, `app_version`, `device_uid` |
| `/v1/transfer` | POST | קוד החלפת מכשיר (קידומת `FPT-`) | `token`, `public_key`, `name`, `platform`, `app_version`, `device_uid` |
| `/v1/device` | GET | מצב המכשיר | — (טוקן) |
| `/v1/device/vpn` | GET | הגדרות VPN + תעודה (רק מכשיר פעיל) | — (טוקן) |
| `/v1/device/rekey` | POST | מפתח VPN חדש (אותה כתובת/מדיניות) | `public_key` |
| `/v1/device/heartbeat` | POST | דיווח תקופתי | ראו למטה |

**אין המצאת נתיבים.** לקוח ה-Windows אינו דורש שום נתיב חדש בשרת.

## סכמת תשובת ההפעלה (`/v1/enroll`, `/v1/transfer`)

(מ-`service.py: Services.enroll`)
```json
{
  "device_id": 7, "token": "<secret>", "status": "active",
  "level": 2, "level_name": "בינוני",
  "vpn": {
    "address": "10.8.0.10/32", "dns": ["10.8.0.1"], "mtu": 1280,
    "server_public_key": "<wg key>", "preshared_key": "<wg key>",
    "endpoint": "vpn.filterphone.com:51820",
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "persistent_keepalive": 25,
    "endpoint_fallback": "151.145.88.42:51820"
  },
  "ca": { "pem": "<PEM>", "sha256": "<hex>", "name": "FilterPhone CA" }
}
```
אימות שהלקוח מבצע לפני שמירה: `allowed_ips` חייב לכלול `0.0.0.0/0` **וגם** `::/0`
(מנהרה מלאה — split tunnel נדחה); כל המפתחות בפורמט WireGuard תקין; ה-endpoint
תקין; תעודת ה-CA תואמת ל-`sha256`, היא CA חתומה-עצמית בתוקף עם מפתח חזק, ותואמת
ל-pin של הבנייה אם הוגדר. הגדרה לא תקינה **אינה מוחלת** — הקודמת נשמרת.

## heartbeat (`/v1/device/heartbeat`)

נשלח מצב בלבד, בלי תוכן אישי (מתוך השדות ש-`sanitize_heartbeat` שומר):
`app_version`, `device_uid`, `policy_version`, `ca_installed`, ו-
`vpn: { state, handshake_age_s, always_on, lockdown, reconnects, error,
data_ok, data_error, data_fails, data_fail_age_s }`.
המיפוי ל-Windows: `always_on` = שירות המנהרה מותקן (start=auto), `lockdown` =
ה-kill switch פעיל. התשובה כוללת את גרסת המדיניות ומרווח הדיווח.

## טיפול בשגיאות ובמצבי קצה

- `401` — הטוקן לא מזוהה (המכשיר הוסר בשרת). ההגנה נשארת (fail closed); המשתמש מקבל
  הסבר. `403` — קוד/מכשיר לא פעיל. `409` — מפתח כבר רשום. `429` — הגבלת קצב.
  `5xx`/רשת/timeout — חולף, נשמר ומנסים שוב עם backoff.
- הודעת שגיאה בעברית שהשרת שולח (`{"error": "..."}`) מוצגת למשתמש כפי שהיא.
- מפתח פרטי אבד (למשל אחרי שחזור) → `rekey` עם מפתח חדש, אותה כתובת ומדיניות.
- רוטציית תעודה מזוהה ב-`/v1/device/vpn` ומטופלת בבטחה (ARCHITECTURE/SECURITY).

## בדיקות חוזה

`tests/FilterPhone.Core.Tests/BackendContractTests.cs` מריץ את **קוד השרת האמיתי**
מקומית (`tests/contract/backend_harness.py` מריץ את `yeled-tov/filterphone/server`
בקומיט נעוץ, עם אותם test doubles של השרת ל-WireGuard ול-Redis). נבדקים: הפעלה
תקינה וקוד שגוי, ייחודיות מפתח וכתובת לכל מכשיר, איסור שימוש חוזר במפתח, טוקן לא
תקין, הגדרת VPN חסרה, heartbeat ו-rekey, ושהשרת רושם `platform=windows`. הבדיקות
**נכשלות** אם ה-harness לא רץ (לא עוברות בשקט).

## אם נדרש שינוי בשרת

כרגע לא נדרש. אם בעתיד יידרש נתיב lifecycle חסר — יש ליישם אותו בשינוי נפרד ומתוחם
בשרת, עם בדיקות, הגירות אם צריך ודרישת פריסה מתועדת, ולעולם לא לפרוס בשקט לייצור.
