# FilterPhone — ניקוי שאריות מדיניות ("מצב ניהול" / "Managed by your organization")
# מסיר את כל המדיניות ש-FilterPhone למחשב כתב, גם אחרי שהתוכנה כבר הוסרה. משתמש רק ברכיבי Windows
# המובנים (רישום, PowerShell, AppLocker). אינו נוגע במדיניות של גורם אחר.
#
# הרצה כמנהל: לחיצה ימנית על Start -> "Terminal (Admin)" / "Windows PowerShell (Admin)", ואז:
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\FilterPhone-Clean-Policies.ps1
# אחרי הסיום: לסגור ולפתוח מחדש את Chrome (או להפעיל מחדש את המחשב) כדי ש-"Managed by your organization"
# ייעלם — Chrome שומר את זה בזיכרון עד הפעלה מחדש.

$ErrorActionPreference = 'Continue'
$HKLM = 'HKLM:\'
$removed = 0

function Remove-Val($path, $name) {
    $full = $HKLM + $path
    if (Test-Path $full) {
        $p = Get-ItemProperty -Path $full -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $p) {
            Remove-ItemProperty -Path $full -Name $name -ErrorAction SilentlyContinue
            Write-Host "  הוסר ערך: $path\$name" -ForegroundColor DarkGray
            $script:removed++
        }
    }
}

function Remove-KeyIfOurs($path) {
    $full = $HKLM + $path
    if (Test-Path $full) {
        Remove-Item -Path $full -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  הוסר מפתח: $path" -ForegroundColor DarkGray
        $script:removed++
    }
}

function Remove-KeyIfEmpty($path) {
    $full = $HKLM + $path
    if (Test-Path $full) {
        $k = Get-Item $full
        if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) {
            Remove-Item -Path $full -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "מנקה מדיניות של FilterPhone..." -ForegroundColor Cyan

# מדיניות Chrome (זה מה שגורם ל-"Managed by your organization")
$chrome = 'SOFTWARE\Policies\Google\Chrome'
Remove-Val $chrome 'QuicAllowed'
Remove-Val $chrome 'DnsOverHttpsMode'
Remove-Val $chrome 'ProxyMode'
# חוסם הפרסומות שהותקן במדיניות (uBlock Origin Lite) + ההגדרות שלו
Remove-KeyIfOurs "$chrome\3rdparty\extensions\ddkjiahejlhfcafbddmgiahcphecmpfh"
$fl = $HKLM + "$chrome\ExtensionInstallForcelist"
if (Test-Path $fl) {
    Get-Item $fl | Select-Object -ExpandProperty Property | ForEach-Object {
        $v = (Get-ItemProperty -Path $fl -Name $_).$_
        if ($v -like 'ddkjiahejlhfcafbddmgiahcphecmpfh*') { Remove-ItemProperty -Path $fl -Name $_ -ErrorAction SilentlyContinue; $removed++ }
    }
    Remove-KeyIfEmpty "$chrome\ExtensionInstallForcelist"
}
Remove-KeyIfEmpty $chrome

# חסימת חנות Microsoft, חסימת התקנת אפליקציות, והפניית קישורים לדפדפן
Remove-Val 'SOFTWARE\Policies\Microsoft\WindowsStore' 'RemoveWindowsStore'
Remove-KeyIfEmpty 'SOFTWARE\Policies\Microsoft\WindowsStore'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\Appx' 'BlockNonAdminUserInstall'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\System' 'DefaultAssociationsConfiguration'

# האפשרויות הנוספות ל-Windows (Copilot, ווידג'טים, Spotlight, חיפוש, אחסון נשלף)
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot'
Remove-Val 'SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSpotlightCollectionOnDesktop'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions'
Remove-Val 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb'
Remove-KeyIfOurs 'SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'

# מפתחות ההסכמה וההגדרות של FilterPhone
Remove-KeyIfOurs 'SOFTWARE\FilterPhone Desktop'

# מדיניות AppLocker שהוחלה דרך ה-CSP (WMI bridge) — מקור נוסף ל"מצב ניהול"
$csp = "root\cimv2\mdm\dmmap"
$parent = "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/FilterPhone"
foreach ($c in @(@('MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03','EXE'),
                 @('MDM_AppLocker_ApplicationLaunchRestrictions01_StoreApps03','StoreApps'))) {
    Get-CimInstance -Namespace $csp -ClassName $c[0] -Filter "ParentID='$parent' and InstanceID='$($c[1])'" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-CimInstance $_ -ErrorAction SilentlyContinue; Write-Host "  הוסרה מדיניות AppLocker (CSP): $($c[1])" -ForegroundColor DarkGray; $removed++ }
}

# מדיניות AppLocker מקומית — מנקים רק אם היא של FilterPhone
try {
    Import-Module AppLocker -ErrorAction Stop
    $local = (Get-AppLockerPolicy -Local -Xml)
    if ($local -match 'FilterPhone') {
        $empty = Join-Path $env:TEMP 'fp-empty-applocker.xml'
        '<AppLockerPolicy Version="1"></AppLockerPolicy>' | Set-Content -Path $empty -Encoding UTF8
        Set-AppLockerPolicy -XmlPolicy $empty -ErrorAction SilentlyContinue
        Remove-Item $empty -ErrorAction SilentlyContinue
        Write-Host "  נוקתה מדיניות AppLocker מקומית" -ForegroundColor DarkGray
        $removed++
    }
} catch { }

gpupdate /target:computer /force | Out-Null

Write-Host ""
if ($removed -gt 0) {
    Write-Host "בוצע. הוסרו $removed פריטי מדיניות של FilterPhone." -ForegroundColor Green
} else {
    Write-Host "לא נמצאו שאריות מדיניות של FilterPhone (אולי כבר נוקו)." -ForegroundColor Green
}
Write-Host 'סגרו ופתחו מחדש את Chrome (או הפעילו מחדש את המחשב) כדי ש-"Managed by your organization" ייעלם.' -ForegroundColor Green
