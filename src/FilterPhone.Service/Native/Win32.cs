using System.Runtime.InteropServices;

namespace FilterPhone.Service.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct DATA_BLOB
{
    public uint cbData;
    public IntPtr pbData;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WINTRUST_FILE_INFO
{
    public uint cbStruct;
    public IntPtr pcwszFilePath;
    public IntPtr hFile;
    public IntPtr pgKnownSubject;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WINTRUST_DATA
{
    public uint cbStruct;
    public IntPtr pPolicyCallbackData;
    public IntPtr pSIPClientData;
    public uint dwUIChoice;
    public uint fdwRevocationChecks;
    public uint dwUnionChoice;
    public IntPtr pFile;
    public uint dwStateAction;
    public IntPtr hWVTStateData;
    public IntPtr pwszURLReference;
    public uint dwProvFlags;
    public uint dwUIContext;
    public IntPtr pSignatureSettings;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct STARTUPINFOW
{
    public uint cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    public ushort wShowWindow, cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

internal static unsafe partial class Win32
{
    public const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const int ERROR_ACCESS_DISABLED_BY_POLICY = 1260;
    public const int ERROR_FILE_NOT_FOUND = 2;
    public const uint INVALID_SESSION = 0xFFFFFFFF;

    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [LibraryImport("crypt32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptProtectData(DATA_BLOB* dataIn, string? description, DATA_BLOB* entropy,
        IntPtr reserved, IntPtr prompt, uint flags, DATA_BLOB* dataOut);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptUnprotectData(DATA_BLOB* dataIn, IntPtr* description, DATA_BLOB* entropy,
        IntPtr reserved, IntPtr prompt, uint flags, DATA_BLOB* dataOut);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr LocalFree(IntPtr mem);

    [LibraryImport("wintrust.dll")]
    internal static partial int WinVerifyTrust(IntPtr hwnd, Guid* action, WINTRUST_DATA* data);

    [LibraryImport("kernel32.dll")]
    internal static partial uint WTSGetActiveConsoleSessionId();

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [LibraryImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcessAsUser(IntPtr token, string applicationName, char* commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags, IntPtr environment, string currentDirectory, STARTUPINFOW* startupInfo,
        PROCESS_INFORMATION* processInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateProcess(IntPtr process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);
}
