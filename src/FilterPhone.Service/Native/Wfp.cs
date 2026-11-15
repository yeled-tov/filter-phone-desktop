using System.Runtime.InteropServices;

namespace FilterPhone.Service.Native;

// Windows Filtering Platform declarations (fwpmu.h / fwpmtypes.h / fwptypes.h), x64 layout.
// Sizes and offsets are cross-checked against wireguard-windows tunnel/firewall/types_windows_64.go
// and asserted at runtime by FilterPhone.Windows.Tests (WfpLayoutTests).

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0
{
    public IntPtr name;          // wchar_t*
    public IntPtr description;   // wchar_t*
}

/// <summary>FWP_VALUE0 / FWP_CONDITION_VALUE0: a type tag and an 8-byte union (inline small integers or a pointer).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct FWP_VALUE0
{
    public uint type;
    public IntPtr value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public uint matchType;
    public FWP_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;
    public Guid filterType;      // union { filterType; calloutKey }
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWPM_FILTER0_CONTEXT
{
    [FieldOffset(0)] public ulong rawContext;
    [FieldOffset(0)] public Guid providerContextKey;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;               // GUID*
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;           // FWPM_FILTER_CONDITION0*
    public FWPM_ACTION0 action;
    public FWPM_FILTER0_CONTEXT context;
    public IntPtr reserved;                  // GUID*
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public IntPtr serviceName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;               // GUID*
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_V4_ADDR_AND_MASK
{
    public uint addr;                        // host byte order
    public uint mask;                        // host byte order
}

[StructLayout(LayoutKind.Sequential, Size = 17)]
internal unsafe struct FWP_V6_ADDR_AND_MASK
{
    public fixed byte addr[16];
    public byte prefixLength;
}

internal static class WfpConst
{
    public const uint RPC_C_AUTHN_WINNT = 10;

    public const uint FWP_UINT8 = 1;
    public const uint FWP_UINT16 = 2;
    public const uint FWP_UINT32 = 3;
    public const uint FWP_UINT64 = 4;
    public const uint FWP_BYTE_ARRAY16_TYPE = 11;
    public const uint FWP_BYTE_BLOB_TYPE = 12;
    public const uint FWP_V4_ADDR_MASK = 0x100;
    public const uint FWP_V6_ADDR_MASK = 0x101;

    public const uint FWP_MATCH_EQUAL = 0;
    public const uint FWP_MATCH_FLAGS_ALL_SET = 6;

    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;

    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;

    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    public static readonly Guid FWPM_CONDITION_FLAGS = new("632ce23b-5167-435c-86d7-e903684aa80c");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_ADDRESS = new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_PORT = new("0c1ba1af-5765-453f-af22-a8f791ac775b");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    public static readonly Guid FWPM_CONDITION_ALE_APP_ID = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
}

internal static unsafe partial class Fwpuclnt
{
    private const string Dll = "fwpuclnt.dll";

    [LibraryImport(Dll)]
    internal static partial uint FwpmEngineOpen0(char* serverName, uint authnService, void* authIdentity, void* session, out IntPtr engineHandle);

    [LibraryImport(Dll)]
    internal static partial uint FwpmEngineClose0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    internal static partial uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [LibraryImport(Dll)]
    internal static partial uint FwpmTransactionCommit0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    internal static partial uint FwpmTransactionAbort0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    internal static partial uint FwpmProviderAdd0(IntPtr engineHandle, FWPM_PROVIDER0* provider, void* sd);

    [LibraryImport(Dll)]
    internal static partial uint FwpmProviderDeleteByKey0(IntPtr engineHandle, Guid* key);

    [LibraryImport(Dll)]
    internal static partial uint FwpmSubLayerAdd0(IntPtr engineHandle, FWPM_SUBLAYER0* subLayer, void* sd);

    [LibraryImport(Dll)]
    internal static partial uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, Guid* key);

    [LibraryImport(Dll)]
    internal static partial uint FwpmFilterAdd0(IntPtr engineHandle, FWPM_FILTER0* filter, void* sd, ulong* id);

    [LibraryImport(Dll)]
    internal static partial uint FwpmFilterDeleteByKey0(IntPtr engineHandle, Guid* key);

    [LibraryImport(Dll)]
    internal static partial uint FwpmFilterGetByKey0(IntPtr engineHandle, Guid* key, FWPM_FILTER0** filter);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial uint FwpmGetAppIdFromFileName0(string fileName, FWP_BYTE_BLOB** appId);

    [LibraryImport(Dll)]
    internal static partial void FwpmFreeMemory0(void** p);
}
