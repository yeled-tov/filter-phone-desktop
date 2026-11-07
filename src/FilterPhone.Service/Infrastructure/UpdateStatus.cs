using FilterPhone.Core.Update;

namespace FilterPhone.Service.Infrastructure;

/// <summary>The current automatic-update state, shared from the UpdateManager to the UI snapshot. Thread-safe.</summary>
internal sealed class UpdateStatus
{
    private readonly object _gate = new();
    private UpdateState _state = UpdateState.Unknown;
    private string? _version;

    public (UpdateState State, string? Version) Read()
    {
        lock (_gate)
        {
            return (_state, _version);
        }
    }

    public void Set(UpdateState state, string? version = null)
    {
        lock (_gate)
        {
            _state = state;
            _version = version;
        }
    }
}
