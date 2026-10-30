using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using FilterPhone.Core.Network;
using FilterPhone.Service.Native;

namespace FilterPhone.Service.Network;

public sealed class WfpException(string operation, uint code)
    : Exception($"WFP {operation} failed with 0x{code:x8}")
{
    public uint Code { get; } = code;
}

/// <summary>
/// Installs the fail-closed network policy (<see cref="KillSwitchPlan"/>) as persistent WFP filters.
///
/// Every object lives under one FilterPhone provider and one sub-layer with fixed keys, and filter keys are
/// derived from the rule index, so removal deletes exactly what we created and nothing else. Filters are
/// persistent: they stay in force across service crashes and reboots until the service (or the elevated
/// uninstaller / recovery command) removes them. All changes are made in one WFP transaction.
/// </summary>
internal static unsafe class WfpKillSwitch
{
    public static readonly Guid ProviderKey = new("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9a01");
    public static readonly Guid SubLayerKey = new("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9a02");
    public const int MaxFilters = 64;

    public static Guid FilterKey(int index)
    {
        if (index is < 0 or >= MaxFilters)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }
        var bytes = new Guid("f1e7c3a0-6f2b-4d8e-9a4b-2c5d7e8f9b00").ToByteArray();
        bytes[15] = (byte)index;
        return new Guid(bytes);
    }

    /// <summary>Replaces the installed rules with <paramref name="rules"/> atomically.</summary>
    public static void Apply(IReadOnlyList<KillSwitchRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.Count > MaxFilters)
        {
            throw new ArgumentException("Too many rules.", nameof(rules));
        }
        using var engine = Engine.Open();
        Check("FwpmTransactionBegin0", Fwpuclnt.FwpmTransactionBegin0(engine.Handle, 0));
        var committed = false;
        try
        {
            EnsureProviderAndSubLayer(engine.Handle);
            DeleteFilters(engine.Handle);
            for (var i = 0; i < rules.Count; i++)
            {
                AddFilter(engine.Handle, rules[i], FilterKey(i));
            }
            Check("FwpmTransactionCommit0", Fwpuclnt.FwpmTransactionCommit0(engine.Handle));
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                _ = Fwpuclnt.FwpmTransactionAbort0(engine.Handle);
            }
        }
    }

    /// <summary>Removes every FilterPhone filter, the sub-layer and the provider. Safe to call when nothing is installed.</summary>
    public static void Remove()
    {
        using var engine = Engine.Open();
        Check("FwpmTransactionBegin0", Fwpuclnt.FwpmTransactionBegin0(engine.Handle, 0));
        var committed = false;
        try
        {
            DeleteFilters(engine.Handle);
            var sub = SubLayerKey;
            var r = Fwpuclnt.FwpmSubLayerDeleteByKey0(engine.Handle, &sub);
            if (r != 0 && r != WfpConst.FWP_E_SUBLAYER_NOT_FOUND)
            {
                throw new WfpException("FwpmSubLayerDeleteByKey0", r);
            }
            var prov = ProviderKey;
            r = Fwpuclnt.FwpmProviderDeleteByKey0(engine.Handle, &prov);
            if (r != 0 && r != WfpConst.FWP_E_PROVIDER_NOT_FOUND)
            {
                throw new WfpException("FwpmProviderDeleteByKey0", r);
            }
            Check("FwpmTransactionCommit0", Fwpuclnt.FwpmTransactionCommit0(engine.Handle));
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                _ = Fwpuclnt.FwpmTransactionAbort0(engine.Handle);
            }
        }
    }

    /// <summary>How many of our filters are currently installed (0 = no network lock).</summary>
    public static int InstalledFilterCount()
    {
        using var engine = Engine.Open();
        var count = 0;
        for (var i = 0; i < MaxFilters; i++)
        {
            var key = FilterKey(i);
            FWPM_FILTER0* filter = null;
            if (Fwpuclnt.FwpmFilterGetByKey0(engine.Handle, &key, &filter) == 0)
            {
                count++;
                Fwpuclnt.FwpmFreeMemory0((void**)&filter);
            }
        }
        return count;
    }

    private static void EnsureProviderAndSubLayer(IntPtr engine)
    {
        using var mem = new Arena();
        var provider = new FWPM_PROVIDER0
        {
            providerKey = ProviderKey,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = mem.String("FilterPhone Desktop"),
                description = mem.String("FilterPhone fail-closed network protection"),
            },
            flags = WfpConst.FWPM_PROVIDER_FLAG_PERSISTENT,
        };
        var r = Fwpuclnt.FwpmProviderAdd0(engine, &provider, null);
        if (r != 0 && r != WfpConst.FWP_E_ALREADY_EXISTS)
        {
            throw new WfpException("FwpmProviderAdd0", r);
        }
        var providerKey = mem.Struct(ProviderKey);
        var sub = new FWPM_SUBLAYER0
        {
            subLayerKey = SubLayerKey,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = mem.String("FilterPhone Desktop network lock"),
                description = mem.String("Blocks traffic outside the FilterPhone tunnel"),
            },
            flags = WfpConst.FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey = providerKey,
            weight = 0xFFFF,
        };
        r = Fwpuclnt.FwpmSubLayerAdd0(engine, &sub, null);
        if (r != 0 && r != WfpConst.FWP_E_ALREADY_EXISTS)
        {
            throw new WfpException("FwpmSubLayerAdd0", r);
        }
    }

    private static void DeleteFilters(IntPtr engine)
    {
        for (var i = 0; i < MaxFilters; i++)
        {
            var key = FilterKey(i);
            var r = Fwpuclnt.FwpmFilterDeleteByKey0(engine, &key);
            if (r != 0 && r != WfpConst.FWP_E_FILTER_NOT_FOUND)
            {
                throw new WfpException("FwpmFilterDeleteByKey0", r);
            }
        }
    }

    private static void AddFilter(IntPtr engine, KillSwitchRule rule, Guid key)
    {
        using var mem = new Arena();
        var conditions = new List<FWPM_FILTER_CONDITION0>();
        var v4 = rule.Family == AddressFamily.InterNetwork;

        if (rule.Loopback)
        {
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_FLAGS, WfpConst.FWP_MATCH_FLAGS_ALL_SET,
                WfpConst.FWP_UINT32, (IntPtr)WfpConst.FWP_CONDITION_FLAG_IS_LOOPBACK));
        }
        if (rule.Protocol != RuleProtocol.Any)
        {
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_PROTOCOL, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_UINT8, (IntPtr)(byte)rule.Protocol));
        }
        if (rule.LocalPort is ushort lp)
        {
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_LOCAL_PORT, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_UINT16, (IntPtr)lp));
        }
        if (rule.RemotePort is ushort rp)
        {
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_REMOTE_PORT, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_UINT16, (IntPtr)rp));
        }
        if (rule.LocalAddress is IPAddress local)
        {
            if (local.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Local address conditions are IPv4 only.", nameof(rule));
            }
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_LOCAL_ADDRESS, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_UINT32,
                (IntPtr)HostOrder(local)));
        }
        // Several remote networks: WFP ORs conditions that share the same field key.
        foreach (var (address, prefix) in rule.RemoteNetworks)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                var p = mem.Struct(new FWP_V4_ADDR_AND_MASK { addr = HostOrder(address), mask = mask });
                conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_REMOTE_ADDRESS, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_V4_ADDR_MASK, p));
            }
            else
            {
                var v6 = new FWP_V6_ADDR_AND_MASK { prefixLength = (byte)prefix };
                address.GetAddressBytes().CopyTo(new Span<byte>(v6.addr, 16));
                var p = mem.Struct(v6);
                conditions.Add(Cond(WfpConst.FWPM_CONDITION_IP_REMOTE_ADDRESS, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_V6_ADDR_MASK, p));
            }
        }
        if (rule.ApplicationPath is string app)
        {
            FWP_BYTE_BLOB* appId = null;
            Check("FwpmGetAppIdFromFileName0", Fwpuclnt.FwpmGetAppIdFromFileName0(app, &appId));
            var appIdPtr = (IntPtr)appId;
            mem.OnDispose(() =>
            {
                var p = (void*)appIdPtr;
                Fwpuclnt.FwpmFreeMemory0(&p);
            });
            conditions.Add(Cond(WfpConst.FWPM_CONDITION_ALE_APP_ID, WfpConst.FWP_MATCH_EQUAL, WfpConst.FWP_BYTE_BLOB_TYPE, (IntPtr)appId));
        }

        var condArray = mem.Array(conditions);
        var filter = new FWPM_FILTER0
        {
            filterKey = key,
            displayData = new FWPM_DISPLAY_DATA0 { name = mem.String("FilterPhone: " + rule.Name), description = mem.String("FilterPhone Desktop") },
            flags = WfpConst.FWPM_FILTER_FLAG_PERSISTENT,
            providerKey = mem.Struct(ProviderKey),
            layerKey = v4 ? WfpConst.FWPM_LAYER_ALE_AUTH_CONNECT_V4 : WfpConst.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey = SubLayerKey,
            weight = new FWP_VALUE0 { type = WfpConst.FWP_UINT8, value = (IntPtr)rule.Weight },
            numFilterConditions = (uint)conditions.Count,
            filterCondition = condArray,
            action = new FWPM_ACTION0 { type = rule.Action == RuleAction.Permit ? WfpConst.FWP_ACTION_PERMIT : WfpConst.FWP_ACTION_BLOCK },
        };
        ulong id = 0;
        Check("FwpmFilterAdd0(" + rule.Name + ")", Fwpuclnt.FwpmFilterAdd0(engine, &filter, null, &id));
    }

    private static FWPM_FILTER_CONDITION0 Cond(Guid field, uint match, uint type, IntPtr value) =>
        new() { fieldKey = field, matchType = match, conditionValue = new FWP_VALUE0 { type = type, value = value } };

    private static uint HostOrder(IPAddress v4) => BinaryPrimitives.ReadUInt32BigEndian(v4.GetAddressBytes());

    private static void Check(string op, uint code)
    {
        if (code != 0)
        {
            throw new WfpException(op, code);
        }
    }

    private sealed class Engine : IDisposable
    {
        public IntPtr Handle { get; private init; }

        public static Engine Open()
        {
            Check("FwpmEngineOpen0", Fwpuclnt.FwpmEngineOpen0(null, WfpConst.RPC_C_AUTHN_WINNT, null, null, out var h));
            return new Engine { Handle = h };
        }

        public void Dispose() => _ = Fwpuclnt.FwpmEngineClose0(Handle);
    }

    /// <summary>Unmanaged allocations that live until the WFP call that uses them has returned.</summary>
    private sealed class Arena : IDisposable
    {
        private readonly List<IntPtr> _blocks = [];
        private readonly List<Action> _cleanups = [];

        public IntPtr String(string s)
        {
            var p = Marshal.StringToHGlobalUni(s);
            _blocks.Add(p);
            _strings.Add(p);
            return p;
        }

        public IntPtr Struct<T>(T value) where T : unmanaged
        {
            var p = (IntPtr)NativeMemory.AllocZeroed((nuint)sizeof(T));
            *(T*)p = value;
            _blocks.Add(p);
            return p;
        }

        public IntPtr Array<T>(List<T> items) where T : unmanaged
        {
            if (items.Count == 0)
            {
                return IntPtr.Zero;
            }
            var p = (IntPtr)NativeMemory.AllocZeroed((nuint)(sizeof(T) * items.Count));
            for (var i = 0; i < items.Count; i++)
            {
                ((T*)p)[i] = items[i];
            }
            _blocks.Add(p);
            return p;
        }

        public void OnDispose(Action a) => _cleanups.Add(a);

        public void Dispose()
        {
            foreach (var c in _cleanups)
            {
                c();
            }
            foreach (var p in _blocks)
            {
                // Strings come from AllocHGlobal, structs from NativeMemory; both are freed by their own allocator.
                if (_strings.Contains(p))
                {
                    Marshal.FreeHGlobal(p);
                }
                else
                {
                    NativeMemory.Free((void*)p);
                }
            }
        }

        private readonly HashSet<IntPtr> _strings = [];
    }
}
