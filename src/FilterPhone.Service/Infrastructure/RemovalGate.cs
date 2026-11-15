using FilterPhone.Core.Removal;

namespace FilterPhone.Service.Infrastructure;

/// <summary>
/// Whether this PC may be cleaned up (uninstall or network-lock removal) right now: either no removal code is
/// needed (see <see cref="RemovalPolicy.IsCodeRequired"/>) or a valid code was entered in the last 30 minutes.
/// This is a guard against casual removal by the PC's users, not a defence against its administrator, who
/// controls Windows itself (see docs/LIMITATIONS.md).
/// </summary>
internal static class RemovalGate
{
    public static bool CodeRequired(MachineState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return RemovalPolicy.IsCodeRequired(state.Enrolled, SecretStore.Has(SecretStore.RemovalKey), state.ServerStatus);
    }

    public static bool Allowed(MachineState state, DateTimeOffset now) =>
        !CodeRequired(state) || RemovalPolicy.IsAuthorized(state.RemovalAuthorizedUntil, now);
}
