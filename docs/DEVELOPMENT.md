# פיתוח ובדיקות

## דרישות
- .NET 10 SDK (ראו `global.json`). פיתוח ובנייה של כל הרכיבים אפשריים גם על
  לינוקס/מק (`EnableWindowsTargeting`); **הרצת** הרכיבים דורשת Windows.

## בנייה ובדיקות
```bash
dotnet restore FilterPhone.Desktop.slnx --locked-mode
dotnet build   FilterPhone.Desktop.slnx -c Release          # אזהרות = שגיאות
dotnet test tests/FilterPhone.Core.Tests --filter "Category!=Contract"   # 111, כל OS
dotnet format  FilterPhone.Desktop.slnx --verify-no-changes  # נאכף ב-CI
```

## בדיקות חוזה מול השרת האמיתי (מקומי)
```bash
# שרת ה-API של yeled-tov/filterphone צריך להיות זמין מקומית:
python -m pip install fastapi "uvicorn[standard]" pydantic argon2-cffi redis fakeredis pillow segno cryptography numpy
python -I tests/contract/backend_harness.py /path/to/filterphone/server 8765 /tmp/contract.json &
FP_CONTRACT_INFO=/tmp/contract.json dotnet test tests/FilterPhone.Core.Tests --filter "Category=Contract"
```

## בדיקות Windows (מורשות)
`tests/FilterPhone.Windows.Tests` רצות על Windows בהרשאות מנהל. הן משתמשות בטווחי
TEST-NET ל-WFP כדי לא לנתק את המכונה, אך עדיף להריץ ב-VM חד-פעמי. AppLocker דורש
משתנה `FP_TEST_STANDARD_USER` (ה-CI יוצר חשבון רגיל) ו-Chrome מותקן.

## הרצה מקומית
- `dotnet run --project src/FilterPhone.App` — הממשק (מתחבר לשירות אם מותקן).
- `dotnet publish src/FilterPhone.Service -r win-x64` ואז התקנה כשירות לבדיקה.
- **אל תפעילו אכיפה (kill switch / AppLocker) על מחשב הפיתוח הראשי** — השתמשו ב-VM.

## דגלי בנייה (build-time)
`FpApiBaseUrl`, `FpSupportWhatsApp`, `FpSupportEmail`, `FpExpectedCaSha256`,
`FpChannel` (Core); `FpUpdateManifestUrl`, `FpUpdatePublisher` (App). ברירות מחדל:
README / config.dart. סודות אינם נדרשים ואינם מגיעים לקוד המקור.
