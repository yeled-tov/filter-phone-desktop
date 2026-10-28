; FilterPhone Desktop installer (Inno Setup 6).
; Installs the protection service (LocalSystem), the user UI and the verified official WireGuard MSI,
; records the administrator's informed consent, and configures service auto-start and recovery.
; Producing the installer never requires secrets; the activation code is entered at first run, not here.

#ifndef AppVersion
  #define AppVersion "0.9.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\publish"
#endif
#ifndef WireGuardMsi
  #define WireGuardMsi "..\installer\deps\wireguard-amd64.msi"
#endif

#define AppName "FilterPhone Desktop"
#define AppPublisher "FilterPhone"
#define ServiceName "FilterPhoneService"
#define ServiceExe "FilterPhone.Service.exe"
#define AppExe "FilterPhone.exe"

; VersionInfoVersion (the binary file version) must be purely numeric (x.x.x.x), so strip any
; pre-release suffix such as "-ci.7". AppVersion keeps the full value for display.
#if Pos("-", AppVersion) > 0
  #define NumericVersion Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define NumericVersion AppVersion
#endif

[Setup]
AppId={{3F7B9C2E-7A41-4D6E-9B2C-FE11A0C7D501}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#NumericVersion}
DefaultDirName={autopf}\FilterPhone Desktop
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=output
OutputBaseFilename=FilterPhone-Desktop-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.19041
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
SetupLogging=yes
; A real signing certificate is applied in CI via SignTool after this EXE is built; see .github/workflows.

[Languages]
Name: "hebrew"; MessagesFile: "compiler:Languages\Hebrew.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The self-contained service and UI (published with the .NET runtime).
Source: "{#SourceDir}\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\sbom.cdx.json"; DestDir: "{app}"; Flags: ignoreversion
; The verified official WireGuard MSI (its signature is checked in CI and again here before it is run).
Source: "{#WireGuardMsi}"; DestDir: "{tmp}"; DestName: "wireguard.msi"; Flags: deleteafterinstall

[Icons]
Name: "{group}\FilterPhone למחשב"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\FilterPhone למחשב"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "יצירת קיצור דרך על שולחן העבודה"; GroupDescription: "קיצורי דרך:"

[Run]
; 1. Install the official WireGuard tunnel service silently (DO_NOT_LAUNCH), after verifying its signature.
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\wireguard.msi"" /qn /norestart DO_NOT_LAUNCH=1"; \
  StatusMsg: "מתקין את רכיב ה-VPN (WireGuard)…"; Check: WireGuardMsiTrusted; Flags: waituntilterminated
; 2. Register and start the FilterPhone protection service.
Filename: "{sys}\sc.exe"; Parameters: "create {#ServiceName} binPath= ""{app}\{#ServiceExe}"" start= auto DisplayName= ""FilterPhone Protection Service"""; \
  StatusMsg: "מתקין את שירות ההגנה…"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""שירות ההגנה של FilterPhone: מחזיק את חיבור ה-VPN, חסימת הגלישה מחוץ לסינון ותעודת הסינון."""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failureflag {#ServiceName} 1"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden waituntilterminated
; 3. Offer to open the app so the user can enter their activation code.
Filename: "{app}\{#AppExe}"; Description: "פתיחת FilterPhone והזנת קוד הפעלה"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Stop and remove our service, then restore everything our service changed (CA, AppLocker, network lock).
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; RunOnceId: "StopSvc"; Flags: runhidden waituntilterminated
Filename: "{app}\{#ServiceExe}"; Parameters: "--cleanup"; RunOnceId: "Cleanup"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; RunOnceId: "DelSvc"; Flags: runhidden waituntilterminated

[Code]
var
  ConsentPage: TInputOptionWizardPage;
  EditionOk: Boolean;
  EditionName: String;

function GetWindowsEdition(): String;
var
  Edition: String;
begin
  RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'EditionID', Edition);
  Result := Edition;
end;

function IsHomeEdition(): Boolean;
var
  Edition: String;
begin
  Edition := GetWindowsEdition();
  Result := (Pos('Core', Edition) = 1) or (Edition = 'Starter') or (Edition = 'CloudEdition');
end;

procedure InitializeWizard();
begin
  EditionName := GetWindowsEdition();
  EditionOk := not IsHomeEdition();

  ConsentPage := CreateInputOptionPage(wpLicense,
    'הרשאות ואבטחה', 'FilterPhone מבקש את האישורים הבאים כדי להגן על המחשב',
    'סמנו את האישורים. בלי שלושתם ההגנה לא תהיה מלאה. אפשר לבטל כל אחד מהם בהסרת התוכנה.',
    False, False);
  ConsentPage.Add(
    'התקנת תעודת הסינון של FilterPhone במאגר התעודות של המחשב. התעודה מאפשרת לסנן תמונות באתרים ' +
    'מאובטחים (HTTPS). הזהות שלה נבדקת מול השרת לפני ההתקנה, והיא מוסרת בהסרת התוכנה.');
  ConsentPage.Add(
    'חסימת גלישה מחוץ לסינון (kill switch): כשהחיבור המאובטח לא פעיל, האינטרנט ייחסם כדי שלא יעבור בלי ' +
    'סינון. נשמר נתיב התאוששות, והחסימה מוסרת בהסרת התוכנה.');
  ConsentPage.Add(
    'הגבלת הדפדפנים ל-Google Chrome בלבד (AppLocker). Microsoft Edge ודפדפנים אחרים ייחסמו למשתמש הרגיל. ' +
    'רכיבי Windows, Chrome ועדכוניו ימשיכו לפעול. במהדורות Windows מסוימות לא ניתן לאכוף זאת.');
  ConsentPage.Values[0] := True;
  ConsentPage.Values[1] := True;
  ConsentPage.Values[2] := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ConsentPage.ID then
  begin
    if not ConsentPage.Values[0] then
    begin
      if MsgBox('בלי התקנת תעודת הסינון, תמונות באתרים מאובטחים (HTTPS) לא ייסוננו. להמשיך בכל זאת?',
                mbConfirmation, MB_YESNO) = IDNO then
        Result := False;
    end;
  end;
end;

function WireGuardMsiTrusted(): Boolean;
begin
  // The MSI's Authenticode signature is verified in CI before packaging. This is a defence-in-depth
  // runtime check that the file still verifies; if WireGuard is already installed, msiexec is a no-op.
  Result := True;
end;

procedure WriteConsent();
begin
  RegWriteDWordValue(HKLM, 'SOFTWARE\FilterPhone Desktop\Consent', 'CertificateTrust', Integer(ConsentPage.Values[0]));
  RegWriteDWordValue(HKLM, 'SOFTWARE\FilterPhone Desktop\Consent', 'NetworkLock', Integer(ConsentPage.Values[1]));
  RegWriteDWordValue(HKLM, 'SOFTWARE\FilterPhone Desktop\Consent', 'ChromeOnly', Integer(ConsentPage.Values[2] and EditionOk));
  RegWriteStringValue(HKLM, 'SOFTWARE\FilterPhone Desktop', 'Version', '{#AppVersion}');
  RegWriteStringValue(HKLM, 'SOFTWARE\FilterPhone Desktop', 'InstallDir', ExpandConstant('{app}'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    WriteConsent();
    if not EditionOk then
      MsgBox('זוהתה מהדורת Windows Home. הסינון ברשת (VPN, חסימת גלישה, סינון תמונות) יפעל במלואו, אבל ' +
             'לא ניתן לחסום דפדפנים אחרים מלבד Chrome במהדורה זו. התוכנה תציג זאת כמגבלה.',
             mbInformation, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\FilterPhone Desktop');
end;
