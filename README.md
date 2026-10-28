# FilterPhone Desktop

סינון אינטרנט ל-Windows 10/11 (x64), בנוי על אותה תשתית סינון של אפליקציית
FilterPhone לאנדרואיד: **VPN (WireGuard)** אל שרת FilterPhone, **סינון DNS**
(AdGuard Home בשרת), **סינון תמונות בצד השרת** (SigLIP2 + NudeNet + סגמנטציה),
עם **חסימת גלישה מחוץ לסינון** (kill switch) ו**הגבלת הדפדפנים ל-Google Chrome**.

> התוכנה הזאת אינה אב-טיפוס. היא מתחברת לשרת FilterPhone האמיתי
> (`https://api.filterphone.com`), מקימה מנהרת VPN ייחודית למחשב, ומסננת תעבורה
> דרך תשתית הסינון הקיימת. "מוגן" מוצג רק אחרי שכל שכבה נבדקה בנפרד ועברה.

מבנה הקוד, מה נבדק ומה עדיין מוגבל — בהמשך ובמסמכים שתחת [`docs/`](docs/).

## הורדה והתקנה

1. הורידו את `FilterPhone-Desktop-Setup.exe` מ-[Releases](../../releases)
   (או מ-Actions → הרצה אחרונה → Artifacts, לבנייה שלא פורסמה).
2. אמתו את ה-SHA‑256 מול הקובץ `FilterPhone-Desktop-Setup.exe.sha256`:
   ```powershell
   (Get-FileHash .\FilterPhone-Desktop-Setup.exe -Algorithm SHA256).Hash
   ```
3. הריצו את ההתקנה ואשרו את בקשת ההרשאות של Windows (UAC).
4. אשרו את האישורים המוסברים (תעודת סינון, חסימת גלישה מחוץ לסינון, Chrome בלבד).
5. בסיום ההתקנה ייפתח החלון; הזינו את **קוד ההפעלה** שקיבלתם מ-FilterPhone.
6. החלון יראה את ההפעלה של כל שכבת הגנה עד שהמצב יהפוך ל**"ההגנה פעילה ומאומתת"**.

אין צורך לפתוח PowerShell, לערוך את הרישום או להריץ כמה מתקינים. אין התקנה שקטה
"בלי UAC" — Windows דורש אישור מנהל להתקנת שירות ו-VPN, וזה לגיטימי.

## מה בונים ואיך (GitHub Actions)

כל דחיפה אמורה לבנות ולבדוק הכול על Windows runner:
`Actions → Build FilterPhone Desktop`.

> **שימו לב:** במאגר הפרטי הזה ריצות ה-Actions על Windows נכשלות כרגע תוך שניות
> ללא הקצאת runner — חסם ברמת חשבון GitHub על runners מתארחים ל-Windows (מכסת
> דקות / תקרת הוצאה), שקיים עוד מאב-הטיפוס. יש לפתור ב-Settings → Billing או
> להשתמש ב-runner עצמי. ה-workflow עצמו תקין. ראו [docs/TESTED.md](docs/TESTED.md). הבנייה כוללת בדיקת פורמט, בנייה עם
אזהרות-כשגיאות, בדיקות יחידה, **בדיקות חוזה מול קוד השרת האמיתי**, בדיקות Windows
(WFP, DPAPI, AppLocker, מאגר תעודות), אימות ה-MSI הרשמי של WireGuard (SHA‑256
וחתימת WireGuard LLC), SBOM, ובניית ה-EXE. לפרסום גרסה: תג `vX.Y.Z` יוצר Release
עם `FilterPhone-Desktop-Setup.exe`.

פרטים: [docs/RELEASE.md](docs/RELEASE.md).

## ארכיטקטורה בקצרה

| רכיב | תפקיד |
|---|---|
| `FilterPhone.Service` (LocalSystem) | כל פעולה מורשית: מנהרת ה-VPN, ה-kill switch, תעודת הסינון, הגבלת הדפדפנים, האימות, ה-IPC |
| `FilterPhone.App` (משתמש רגיל, בלי מנהל) | הממשק בעברית; מדבר עם השירות דרך Named Pipe מאובטח בלבד |
| `FilterPhone.Core` | לוגיקה חוצת-פלטפורמה: לקוח ה-API, אימות הגדרות ה-VPN, המפתחות, בוני המדיניות |
| WireGuard for Windows | שירות המנהרה הרשמי (MSI חתום, מאומת) — לא דרייבר עצמאי |

התרשים המלא, גבולות האבטחה ומודל האיום: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/SECURITY.md](docs/SECURITY.md).

## מה מוכיח שהסינון עובד

החלון וה-API לא מספיקים כהוכחה. השירות בודק כל שכבה בנפרד
([docs/ARCHITECTURE.md#verification](docs/ARCHITECTURE.md#אימות)):

- **מנהרה** — handshake טרי של WireGuard (לא רק "השירות רץ").
- **מסלול השרת** — השרת מדווח שהבקשות מגיעות מכתובת ה-VPN של המכשיר (`via_vpn`),
  ובדיקת תעבורה אמיתית בפורט 80 (כמו `DataProbe` באנדרואיד).
- **יירוט HTTPS** — אתר ציבורי מוגש עם תעודה שהונפקה ע"י תעודת הסינון של המכשיר,
  כלומר ה-TLS באמת מסתיים בפרוקסי הסינון של השרת.
- **מסלול התמונות** — בקשת תמונה עוברת דרך הפרוקסי (כותרת `x-filterphone` /
  תעודת הסינון). רק אז השכבה נחשבת תקינה.
- **Chrome בלבד** — בדיקת הרצה אמיתית בהקשר המשתמש: Chrome מורשה, Edge ודפדפן
  נייד נחסמים ע"י Windows.

## מגבלות שחשוב להכיר

- **Windows Home**: אין AppLocker — הסינון ברשת פועל במלואו, אך לא ניתן לחסום
  דפדפנים אחרים. התוכנה מציגה זאת כמגבלה (לא "מוגן").
- **מנהל מקומי**: משתמש עם הרשאות מנהל מלאות יכול בסופו של דבר לעצור או להסיר כל
  תוכנה. ההגנה החזקה מיועדת לחשבון יומי מסוג משתמש רגיל ([docs/SECURITY.md](docs/SECURITY.md)).
- **תעבורה עם certificate pinning** (אפליקציות מסוימות, בנקים): לא ניתנת ליירוט;
  עוברת כמו שהיא, ולכן גם לא מסוננת-תמונות שם — בדיוק כמו בשרת הקיים.
- רשימת המגבלות המלאה: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## פיתוח ובדיקות

```bash
dotnet test tests/FilterPhone.Core.Tests --filter "Category!=Contract"   # 111 בדיקות, כל מערכת הפעלה
```

בדיקות החוזה מול השרת האמיתי ובדיקות Windows (WFP/DPAPI/AppLocker) רצות ב-CI על
Windows. הוראות מלאות: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## חתימת קוד

הבנייה חותמת את ה-EXE ואת ההתקנה רק כשסופק אישור חתימה אמיתי ב-secrets של CI
(`CODE_SIGN_PFX_BASE64`, `CODE_SIGN_PASSWORD`). בלי אישור — הבנייה מצליחה אך
ללא חתימה. חתימה לבדה לא מבטיחה הורדה בלי אזהרת SmartScreen; מוניטין נצבר עם הזמן
([הנחיות Microsoft](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)).

## רישיונות

WireGuard — MIT · .NET — MIT · BouncyCastle — MIT. פירוט מלא ב-SBOM
(`sbom.cdx.json`, CycloneDX) וב-`THIRD-PARTY-NOTICES.txt` שמותקנים עם התוכנה.
