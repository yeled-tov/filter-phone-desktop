# שחרור גרסה ואימות

## בנייה אוטומטית
כל דחיפה ל-`main` או ל-ענף `ccr-*` מריצה את `Build FilterPhone Desktop`:
פורמט → בנייה (אזהרות=שגיאות) → בדיקות יחידה → בדיקות חוזה מול השרת האמיתי →
בדיקות Windows → אימות ה-MSI של WireGuard → publish → SBOM → אימות פלט → חתימה
(אם יש אישור) → בניית ההתקנה → SHA‑256 → העלאת Artifacts. הבנייה **נכשלת בקול** אם
שלב כלשהו נכשל, קובץ חסר, או בדיקה לא רצה.

## הורדת ההתקנה מבנייה (בלי פרסום)
`Actions` → ההרצה → Artifacts → `FilterPhone-Desktop-Setup` (מכיל את ה-EXE,
קובץ ה-SHA‑256 וה-SBOM).

## פרסום גרסה
1. תייגו: `git tag v1.0.0 && git push origin v1.0.0`.
2. הבנייה רצה, ואם התג מתחיל ב-`v` נוצר **GitHub Release** עם
   `FilterPhone-Desktop-Setup.exe`, קובץ ה-SHA‑256 וה-SBOM.
3. הגרסה נגזרת מהתג (`v1.0.0` → `1.0.0`) ונכתבת לכל הרכיבים ולמידע הגרסה של ה-EXE.

## חתימת קוד (אופציונלי, מומלץ)
הוסיפו ב-Settings → Secrets:
- `CODE_SIGN_PFX_BASE64` — ה-PFX מקודד Base64.
- `CODE_SIGN_PASSWORD` — סיסמת ה-PFX.
אז הבנייה חותמת את ה-EXE ואת ההתקנה ב-SignTool עם חותמת זמן. בלי הסודות — הבנייה
מצליחה בלי חתימה. **אל תכניסו מפתחות חתימה, סודות API או סודות VPN למקור.**

## אימות ההורדה (משתמש)
```powershell
(Get-FileHash .\FilterPhone-Desktop-Setup.exe -Algorithm SHA256).Hash
# להשוות ל-FilterPhone-Desktop-Setup.exe.sha256
Get-AuthenticodeSignature .\FilterPhone-Desktop-Setup.exe   # כשחתום
```

## SmartScreen
חתימה לבדה לא מבטיחה הורדה בלי אזהרה; מוניטין נצבר עם הזמן. אם Defender מזהה בנייה
נקייה בטעות — הגשה דרך https://www.microsoft.com/wdsi/filesubmission. אין להשבית
אנטי-וירוס ואין להוסיף חריגות רחבות.
