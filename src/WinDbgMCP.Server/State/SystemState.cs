namespace WinDbgMCP.Server.State;

/// <summary>
/// The system state model. Maintained by StateCoordinator and read by every precondition check.
/// </summary>
public sealed class SystemState
{
    // === VM ===
    public VmPowerState VmPower { get; set; } = VmPowerState.Unknown;

    /// <summary>True when <see cref="VmPower"/> came from a host task result or a vm_* tool; false when the SSH probe inferred it.</summary>
    public bool VmPowerFromHost { get; set; }

    /// <summary>Result of the last guest SSH (TCP 22) probe.</summary>
    public GuestSshState GuestSsh { get; set; } = GuestSshState.Unknown;

    public string? VmIpAddress { get; set; }
    public string VmName { get; set; } = string.Empty;

    // === Kernel debugger ===
    public bool KdConnected { get; set; }
    public KdTransport KdTransportType { get; set; } = KdTransport.None;
    public DebugExecutionStatus KdExecStatus { get; set; } = DebugExecutionStatus.Uninitialized;
    public int PendingEventCount { get; set; }
    public bool IsBugcheck { get; set; }
    public string? BugcheckCode { get; set; }

    // === Derived ===
    /// <summary>VmPower is Running, the guest answers on SSH, and the kernel debugger does not hold it halted.</summary>
    public bool GuestOpsAvailable { get; set; }

    // === User mode ===
    /// <summary>The target of the running Frida background session, or null when none runs.</summary>
    public string? FridaBackgroundTarget { get; set; }
}

public enum VmPowerState
{
    Off,
    Running,
    Paused,
    Saved,
    Unknown,
}

public enum GuestSshState
{
    Unknown,
    Reachable,
    Unreachable,
}

public enum KdTransport
{
    None,
    KDNET,
    Serial,
}

/// <summary>
/// The target's execution status as this server uses it. DbgEngManager maps dbgeng's DEBUG_STATUS values to it
/// by name (the numbers differ).
/// </summary>
public enum DebugExecutionStatus
{
    /// <summary>DbgEng is not loaded or no session was ever opened.</summary>
    Uninitialized,
    NoDebuggee,
    Go,
    Stepping,
    Break,
    Unknown,
}
