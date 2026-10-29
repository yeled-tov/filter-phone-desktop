# ארכיטקטורה — FilterPhone Desktop

## מטרה

להביא את הסינון של FilterPhone לאנדרואיד אל Windows, תוך שימוש חוזר בתשתית
הקיימת (אותו שרת, אותו API, אותו מנוע סינון תמונות, אותה תעודת סינון), בלי להמציא
שירות סינון חדש ובלי לשנות את השרת.

## התרשים הכולל

```
משתמש (Google Chrome בלבד, נאכף ב-AppLocker)
  │
  │  כל התעבורה (IPv4 + IPv6) במנהרת WireGuard — kill switch חוסם כל יציאה אחרת
  ▼
שירות WireGuard for Windows (WireGuardTunnel$FilterPhone)
  │  ← הגדרה מוצפנת DPAPI, מפתח פרטי ייחודי למחשב
  ▼
שרת FilterPhone (api.filterphone.com / vpn.filterphone.com)
  ├─ DNS  ────────────▶ AdGuard Home: חסימת אתרים לכל מכשיר ($client=)
  ├─ HTTP/HTTPS ──────▶ fp-proxy (mitmproxy שקוף): דף "אתר חסום", איסוף תמונות
  │                        ▼ fp-engine: SigLIP2 + ראשים + NudeNet + סגמנטציה
  └─ api.filterphone.com ▶ fp-api: הרשמה/הפעלה, מדיניות, VPN, heartbeat
```

המחשב הוא עוד "מכשיר" מבחינת השרת: הוא נרשם עם `platform=windows`, מקבל כתובת
VPN ומפתח משלו, ומדווח ב-heartbeat בדיוק כמו טלפון.

## רכיבי הקוד (C# / .NET 10)

### FilterPhone.Core — לוגיקה חוצת-פלטפורמה (נבדקת בכל מערכת הפעלה)
- `Api/FilterPhoneApiClient` — לקוח ה-API: `/v1/enroll`, `/v1/transfer`,
  `/v1/device`, `/v1/device/vpn`, `/v1/device/rekey`, `/v1/device/heartbeat`.
  החוזים אומתו מול `server/filterphone/api/app.py` ו-`service.py`.
- `Vpn/` — יצירת מפתחות X25519 (זהים ל-`wg genkey`), אימות הגדרות ה-VPN מהשרת
  (מנהרה מלאה בלבד — split tunnel נדחה), והרכבת קובץ wg-quick.
- `Trust/CaCertificate` — אימות תעודת הסינון (טביעת אצבע, pin, מגבלות CA).
- `Network/KillSwitchPlan` — מדיניות ה-kill switch (ראו SECURITY.md).
- `Policy/` — בניית מדיניות AppLocker ומדיניות Chrome במכונה.
- `Status/ProtectionEvaluator` — הפיכת בדיקות השכבות למצב כולל אחד וישר.
- `Ipc/IpcProtocol`, `Support/`, `Util/Redactor`, `Diagnostics/`.

### FilterPhone.Service — השירות המורשה (LocalSystem)
כל שינוי במחשב נעשה כאן, אף פעם לא ב-UI:
- `Tunnel/TunnelController` — מפעיל את שירות WireGuard הרשמי
  (`wireguard /installtunnelservice`), כותב `*.conf.dpapi` מוצפן, מריץ את
  `wireguard.exe`/`wg.exe` רק אחרי אימות חתימת WireGuard LLC.
- `Network/WfpKillSwitch` — מסננים קבועים ב-WFP (ראו SECURITY.md).
- `Trust/TrustStore` — מוסיף/מסיר את תעודת הסינון ב-`LocalMachine\Root`.
- `Policy/ChromeOnlyEnforcer` + `LaunchProbe` — אכיפת Chrome-בלבד ואימות אמיתי.
- `Policy/BrowserWatchdog` — סוגר מיד כל דפדפן חסום שנפתח, ואת חנות Microsoft אם נבחרה חסימתה (מקביל ל"מגן" באנדרואיד; האכיפה הראשית ב-Home).
- `Policy/AppxPolicyCheck` — שואל את מנוע AppLocker של Windows איך המדיניות מחליטה על אפליקציה ארוזה מותקנת.
- `Verification/NetworkVerifier` — הבדיקות בפועל (HTTPS, תמונה, תעבורה).
- `Engine/ProtectionEngine` — לולאת ההגנה: מיישרת כל שכבה, עם backoff חסום.
- `Ipc/PipeServer` — Named Pipe עם ACL מצמצם ומערכת פקודות קבועה.
- מצבי שורת פקודה: `--cleanup`, `--remove-network-lock`, `--status`,
  `--verify`, `--diagnostics`, `--enroll`, `--removal-status`, `--authorize-removal CODE`.
- `Infrastructure/Choices` — מה נאכף בפועל: הסכמת ההתקנה וגם ההגדרה מהדשבורד.
- `Infrastructure/RemovalGate` + `Core/Removal/RemovalCode` — קוד הסרה מהדשבורד.

### FilterPhone.App — הממשק בעברית (משתמש רגיל, בלי מנהל)
WPF עם `FlowDirection=RightToLeft`, מודע-DPI לכל מסך. מדבר עם השירות דרך ה-pipe
בלבד, ומוודא שהצד השני הוא ה-`FilterPhone.Service.exe` המותקן.

## מחזור ההפעלה (enrollment)

מבוסס על זרימת ההפעלה בקוד של האפליקציה הקיימת
(`app/lib/src/app_controller.dart` → `/v1/enroll`):

1. המחשב יוצר זוג מפתחות WireGuard. **המפתח הפרטי לא עוזב את המחשב.**
2. השירות שולח ל-`/v1/enroll` רק: המפתח הציבורי, קוד ההפעלה, `platform=windows`,
   שם המחשב ומזהה התקנה אקראי. (קוד בקידומת `FPT-` → `/v1/transfer`.)
3. התשובה: טוקן מכשיר, הגדרות VPN ותעודת הסינון. כולם נבדקים לפני שמירה.
4. הטוקן, המפתח הפרטי והגדרות ה-VPN נשמרים מוצפנים ב-DPAPI (רק SYSTEM מפענח).
5. מאוחר יותר ההגדרות מתרעננות דרך `/v1/device/vpn`, והמצב מדווח ב-heartbeat.

אין המצאת נתיבים: כל קריאה היא נתיב קיים ומאומת מהשרת.

## אימות

"מוגן" (`Protected`) מוחזר רק כש**כל** השכבות תקינות וה**אימות טרי** (עד שעתיים):

| שכבה | כיצד מאומתת |
|---|---|
| `tunnel` | handshake טרי מ-`wg show ... latest-handshakes` |
| `server_path` | השרת מדווח `via_vpn=true` + בדיקת תעבורה בפורט 80 |
| `kill_switch` | מספר מסנני ה-WFP שלנו מותקן |
| `ca_trust` | תעודת הסינון מותקנת ב-`LocalMachine\Root` |
| `interception` | אתר ציבורי מוגש בתעודה שהונפקה ע"י תעודת הסינון (ה-TLS מסתיים בפרוקסי) |
| `image_path` | בקשת תמונה עוברת דרך הפרוקסי (כותרת `x-filterphone` / תעודת הסינון) |
| `chrome_only` | בדיקת הרצה: Chrome מורשה, Edge/נייד נחסמים |
| `chrome_policy` | מדיניות Chrome במכונה הוחלה |
| `store_block` | כלל החנות הוחל + `Test-AppLockerPolicy` קובע שחבילת החנות נחסמת + אכיפת AppLocker הוכחה (או "לא התבקש") |

handshake מוצלח **אינו** מוכיח אינטרנט; קריאת API מוצלחת **אינה** מוכיחה מנהרה;
מנהרה פעילה **אינה** מוכיחה סינון תמונות. כל שכבה נבדקת לבדה.

## עמידות

- לולאת הגנה כל 15 שניות, ומיד אחרי שינוי רשת / יציאה משינה / בקשת משתמש.
- כל פעולה מתקנת עוברת דרך backoff חסום (5ש' → 15ד') — בלי לולאה שמרוקנת סוללה.
- חריג בשלב אחד נרשם וממשיך; לעולם לא מפיל את השירות ולא "פותח" את הרשת.
- אחרי אתחול: שירות WireGuard וה-kill switch (מסננים קבועים) חוזרים לבד;
  השירות שלנו מתחיל אוטומטית (start=auto) עם restart-on-failure.
- כש-DNS חסום מחוץ למנהרה — פתרון שם ה-API/endpoint נופל לכתובות שנשמרו.
- כשל רגעי של השרת: הרשת נשארת חסומה (fail closed) עד שהחיבור חוזר.
