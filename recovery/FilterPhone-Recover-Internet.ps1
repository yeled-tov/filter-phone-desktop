# FilterPhone — שחזור אינטרנט חירום
# מסיר את נעילת הרשת (kill switch) של FilterPhone מ-WFP, גם אם תוכנת FilterPhone כבר הוסרה.
# משתמש רק ברכיבים מובנים של Windows (fwpuclnt.dll). אין צורך בחיבור לאינטרנט.
#
# הרצה: לחיצה ימנית על Start -> "Windows PowerShell (Admin)" / "Terminal (Admin)", ואז:
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\FilterPhone-Recover-Internet.ps1
# או להדביק את כל הקובץ לתוך חלון PowerShell של מנהל.

$ErrorActionPreference = 'Stop'

$src = @'
using System;
using System.Runtime.InteropServices;
public static class FpWfp
{
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0(string s, uint a, IntPtr id, IntPtr sess, out IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr h, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr h, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr h, ref Guid key);

    // חייב להתאים ל-WfpKillSwitch.cs
    static readonly Guid Provider = new Guid("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9a01");
    static readonly Guid SubLayer = new Guid("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9a02");
    static readonly Guid FilterBase = new Guid("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9b00");
    const int MaxFilters = 64;
    const uint RPC_C_AUTHN_WINNT = 10;

    static Guid FilterKey(int i) { var b = FilterBase.ToByteArray(); b[15] = (byte)i; return new Guid(b); }

    public static int Run()
    {
        IntPtr h;
        uint r = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out h);
        if (r != 0) { Console.Error.WriteLine("FwpmEngineOpen0 0x" + r.ToString("x8")); return 2; }
        int removed = 0;
        try
        {
            for (int i = 0; i < MaxFilters; i++)
            {
                var k = FilterKey(i);
                if (FwpmFilterDeleteByKey0(h, ref k) == 0) removed++;
            }
            var sub = SubLayer; FwpmSubLayerDeleteByKey0(h, ref sub);
            var prov = Provider; FwpmProviderDeleteByKey0(h, ref prov);
        }
        finally { FwpmEngineClose0(h); }
        return removed;
    }
}
'@

Add-Type -TypeDefinition $src -Language CSharp | Out-Null
$n = [FpWfp]::Run()
if ($n -ge 0) {
    Write-Host ""
    Write-Host ("בוצע. הוסרו $n פילטרים של FilterPhone מ-WFP.") -ForegroundColor Green
    Write-Host "האינטרנט אמור לחזור מיד. אם לא — נתקו וחברו מחדש את הרשת, או הפעילו מחדש את המחשב." -ForegroundColor Green
} else {
    Write-Host "נכשל. ודאו שאתם מריצים כמנהל (Administrator)." -ForegroundColor Red
    exit 1
}
