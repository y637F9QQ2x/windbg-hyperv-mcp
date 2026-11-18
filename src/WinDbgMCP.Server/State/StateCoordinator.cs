using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;

namespace WinDbgMCP.Server.State;

/// <summary>
/// Holds the system state, checks the preconditions of every tool call before it runs, and returns error
/// text that tells the model what to do next.
/// </summary>
public sealed class StateCoordinator
{
    private readonly ServerConfig _config;
    private readonly ILogger<StateCoordinator> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private SystemState _state = new();

    private DateTime _lastProbe = DateTime.MinValue;
    // Debounce a Running->Off demotion from the SSH probe (a dropped packet, a guest rebooting).
    private int _consecutiveUnreachable;

    /// <summary>Minimum time between two SSH probes. Tests shorten it.</summary>
    internal TimeSpan ProbeInterval { get; set; } = TimeSpan.FromSeconds(2);

    public SystemState State => _state;

    // Set when the services are created (delegates avoid circular dependencies during construction).
    public Func<Task<bool>>? ProbeGuestSshAsync { get; set; }
    public Func<DebugExecutionStatus>? GetDbgEngExecutionStatus { get; set; }
    public Func<bool>? IsDbgEngConnected { get; set; }
    public Func<int>? GetPendingEventCount { get; set; }
    public Func<string?>? GetFridaBackgroundTarget { get; set; }

    // Cleanup after vm_stop (ResetAfterStopAsync).
    public Func<Task>? CleanupKdSessionAsync { get; set; }
    public Action? CleanupFridaSession { get; set; }

    public StateCoordinator(ServerConfig config, ILogger<StateCoordinator> logger)
    {
        _config = config;
        _logger = logger;
        _state.VmName = config.Vm.VmName;
        _state.VmIpAddress = config.Vm.GuestIpAddress;
    }

    /// <summary>
    /// Called BEFORE every MCP tool execution. Returns null if the preconditions are met, an error, or a success
    /// that carries a warning. An unknown name is an error, so a tool can never skip its checks by a typo.
    /// </summary>
    public async Task<ToolResult?> ValidatePreconditionsAsync(string toolName)
    {
        await _lock.WaitAsync();
        try
        {
            await RefreshStateCoreAsync();

            return toolName switch
            {
                // --- VM tools ---
                "vm_start" => RequireVmOff(),
                // vm_stop is always allowed: an unreachable guest may be hung, and the host task
                // knows the real state (TurnOff works in any state).
                "vm_stop" => WarnIfKdAttached(),
                "vm_pause" => RequireVmRunning(warnIfKdAttached: true),
                "vm_resume" => RequireVmPaused(),

                // --- Kernel debug tools ---
                "kd_connect" => RequireKdConnectable(),
                "kd_disconnect" or "kd_wait_for_event" => RequireKdConnected(),
                "kd_break" => RequireKdConnected_TargetRunning(),
                "kd_continue" => RequireKdConnected_TargetHalted_CanResume(),
                "kd_step" or "kd_execute" => RequireKdConnected_TargetHalted(),

                // --- Guest and user-mode tools ---
                "guest_run_command" or "guest_transfer_to_vm" or "guest_transfer_from_vm" or
                "umd_frida" or "umd_dbgsrv" or "umd_ttd" => RequireGuestOpsAvailable(),

                // --- Meta ---
                "get_system_state" => null,

                _ => ToolResult.Error($"Internal error: no precondition rule for '{toolName}'."),
            };
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Refresh the state (get_system_state). Takes the same lock as every mutator.</summary>
    public async Task RefreshStateAsync()
    {
        await _lock.WaitAsync();
        try { await RefreshStateCoreAsync(); }
        finally { _lock.Release(); }
    }

    private async Task RefreshStateCoreAsync()
    {
        // 1. Kernel debugger: the execution status the DbgEng event callbacks cached. No COM call.
        if (_state.KdConnected)
        {
            var status = IsDbgEngConnected?.Invoke() == true
                ? GetDbgEngExecutionStatus?.Invoke() ?? DebugExecutionStatus.Unknown
                : DebugExecutionStatus.NoDebuggee;
            _state.KdExecStatus = status;
            if (status == DebugExecutionStatus.NoDebuggee)
            {
                // The session ended underneath us (the VM rebooted or was powered off).
                _logger.LogWarning("Kernel debugger connection lost (no debuggee)");
                _state.KdConnected = false;
                _state.KdTransportType = KdTransport.None;
            }
        }

        _state.PendingEventCount = GetPendingEventCount?.Invoke() ?? 0;
        if (!_state.KdConnected || _state.KdExecStatus != DebugExecutionStatus.Break)
        {
            _state.IsBugcheck = false;
            _state.BugcheckCode = null;
        }

        _state.FridaBackgroundTarget = GetFridaBackgroundTarget?.Invoke();

        // 2. One SSH probe, at most every ProbeInterval. It reliably reports a guest that answers, but cannot
        // see Paused or Saved (a frozen guest looks Off) and cannot tell a dropped packet or a reboot from a
        // power-off. So Paused and Saved (set by vm_* or a host result) are not re-probed, a Running VM is
        // demoted to Off only after two unreachable probes in a row, and a Running VM whose kernel the debugger
        // holds halted is not probed at all (it cannot answer, and each probe would cost VmStateQuerySeconds).
        var kdHalted = _state.KdConnected && _state.KdExecStatus == DebugExecutionStatus.Break;
        if (_state.VmPower is not (VmPowerState.Paused or VmPowerState.Saved) &&
            !(_state.VmPower == VmPowerState.Running && kdHalted) &&
            DateTime.UtcNow - _lastProbe > ProbeInterval &&
            ProbeGuestSshAsync != null)
        {
            try
            {
                if (await ProbeGuestSshAsync())
                {
                    _state.GuestSsh = GuestSshState.Reachable;
                    SetPower(VmPowerState.Running, fromHost: false);
                    _consecutiveUnreachable = 0;
                }
                else
                {
                    _state.GuestSsh = GuestSshState.Unreachable;
                    if (_state.VmPower == VmPowerState.Running)
                    {
                        if (++_consecutiveUnreachable >= 2) SetPower(VmPowerState.Off, fromHost: false);
                    }
                    else
                    {
                        SetPower(VmPowerState.Off, fromHost: _state.VmPower == VmPowerState.Off && _state.VmPowerFromHost);
                        _consecutiveUnreachable = 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Guest SSH probe failed; keeping the last known state");
            }
            _lastProbe = DateTime.UtcNow;
        }

        // 3. Derived
        _state.GuestOpsAvailable =
            _state.VmPower == VmPowerState.Running &&
            _state.GuestSsh == GuestSshState.Reachable &&
            !kdHalted;
    }

    private void SetPower(VmPowerState power, bool fromHost)
    {
        _state.VmPower = power;
        _state.VmPowerFromHost = fromHost;
    }

    /// <summary>
    /// After a successful vm_stop: every session with the guest has ended. Ends the kernel-debug session on the
    /// DbgEng thread and stops a Frida background session, then resets the state to a powered-off VM.
    /// </summary>
    public async Task ResetAfterStopAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (CleanupKdSessionAsync != null)
            {
                try { await CleanupKdSessionAsync(); }
                catch (Exception ex) { _logger.LogWarning(ex, "Kernel debug cleanup after vm_stop failed"); }
            }
            try { CleanupFridaSession?.Invoke(); }
            catch (Exception ex) { _logger.LogWarning(ex, "Frida cleanup after vm_stop failed"); }

            _state = new SystemState
            {
                VmName = _config.Vm.VmName,
                VmIpAddress = _config.Vm.GuestIpAddress,
                VmPower = VmPowerState.Off,
                VmPowerFromHost = true,
                GuestSsh = GuestSshState.Unknown,
                KdExecStatus = DebugExecutionStatus.NoDebuggee,
            };
            _consecutiveUnreachable = 0;
            _lastProbe = DateTime.MinValue;
        }
        finally
        {
            _lock.Release();
        }
    }

    // Every Set* mutator takes _lock. RefreshStateCoreAsync holds _lock across its awaited probe (it yields
    // mid-refresh), so an unlocked Set* running during that yield could be overwritten by the refresh's commit
    // (a Paused VM reported as Off). Deadlock-safe: Set* is only called from tool bodies after
    // ValidatePreconditionsAsync released the lock (and from tests, which hold none); the refresh never calls a
    // mutator; the critical sections have no await.

    /// <summary>Update the state after a successful kd_connect: the target is halted at the initial break.</summary>
    public void SetKdConnected(KdTransport transport)
    {
        _lock.Wait();
        try
        {
            _state.KdConnected = true;
            _state.KdTransportType = transport;
            _state.KdExecStatus = DebugExecutionStatus.Break;
        }
        finally { _lock.Release(); }
    }

    /// <summary>Update the state after kd_disconnect.</summary>
    public void SetKdDisconnected()
    {
        _lock.Wait();
        try
        {
            _state.KdConnected = false;
            _state.KdTransportType = KdTransport.None;
            _state.KdExecStatus = DebugExecutionStatus.NoDebuggee;
            _state.IsBugcheck = false;
            _state.BugcheckCode = null;
        }
        finally { _lock.Release(); }
    }

    /// <summary>Update the state after a successful vm_pause.</summary>
    public void SetVmPaused()
    {
        _lock.Wait();
        try
        {
            SetPower(VmPowerState.Paused, fromHost: true);
            _state.GuestOpsAvailable = false;
            _consecutiveUnreachable = 0;
            _lastProbe = DateTime.UtcNow;   // keep the next refresh from overwriting it at once
        }
        finally { _lock.Release(); }
    }

    /// <summary>Update the state after a successful vm_resume.</summary>
    public void SetVmResumed()
    {
        _lock.Wait();
        try
        {
            SetPower(VmPowerState.Running, fromHost: true);
            _consecutiveUnreachable = 0;
            _lastProbe = DateTime.UtcNow;
        }
        finally { _lock.Release(); }
    }

    /// <summary>
    /// Apply the Hyper-V state that a lab task reported ("Running", "Off", "Paused", "Saved"). This is the
    /// authoritative state, unlike the SSH probe, which cannot tell Off from Paused. Transitional states
    /// ("Starting", "Stopping", ...) and null are ignored.
    /// </summary>
    public void ApplyHostState(string? hyperVState)
    {
        VmPowerState? mapped = hyperVState switch
        {
            "Running" => VmPowerState.Running,
            "Off" => VmPowerState.Off,
            "Paused" => VmPowerState.Paused,
            "Saved" => VmPowerState.Saved,
            _ => null,
        };
        if (mapped == null) return;

        _lock.Wait();
        try
        {
            SetPower(mapped.Value, fromHost: true);
            if (mapped != VmPowerState.Running)
                _state.GuestOpsAvailable = false;
            _consecutiveUnreachable = 0;
            _lastProbe = DateTime.UtcNow;
        }
        finally { _lock.Release(); }
    }

    /// <summary>Record a bugcheck seen at the current break.</summary>
    public void SetBsodDetected(string? bugcheckCode)
    {
        _lock.Wait();
        try
        {
            _state.IsBugcheck = true;
            _state.BugcheckCode = bugcheckCode;
        }
        finally { _lock.Release(); }
    }

    // ===============================================================
    //  PRECONDITION CHECKS
    // ===============================================================

    private ToolResult? RequireVmOff()
    {
        // Start-VM also restores a Saved VM, so vm_start is allowed from Saved too.
        if (_state.VmPower != VmPowerState.Off && _state.VmPower != VmPowerState.Saved)
            return ToolResult.Error(
                $"The VM is {_state.VmPower}. Call vm_stop first, then vm_start. If the VM was stopped outside " +
                "this server, call get_system_state(queryHost=true) so the server learns the real state.");
        return null;
    }

    private ToolResult? WarnIfKdAttached()
    {
        if (_state.KdConnected)
            return ToolResult.Success("WARNING: the kernel debugger session will be lost. Proceeding.");
        return null;
    }

    private ToolResult? RequireVmRunning(bool warnIfKdAttached = false)
    {
        if (_state.VmPower != VmPowerState.Running)
            return ToolResult.Error($"The VM is {_state.VmPower}. Start the VM first with vm_start.");
        if (warnIfKdAttached && _state.KdConnected)
            return ToolResult.Success(
                "WARNING: the kernel debugger also freezes while the VM is paused. Proceeding.");
        return null;
    }

    private ToolResult? RequireVmPaused()
    {
        if (_state.VmPower != VmPowerState.Paused)
            return ToolResult.Error(
                $"The VM is {_state.VmPower}, not paused. Call vm_pause first. If it was paused outside this " +
                "server, call get_system_state(queryHost=true) so the server learns the real state.");
        return null;
    }

    /// <summary>
    /// kd_connect needs no answering guest: a guest that is booting, hung in user mode or without sshd still
    /// answers KDNET, and debugging such a guest is the point of a kernel debugger. Refused only when KD is
    /// already connected, or when the host (not the SSH probe) reports the VM is off, paused or saved.
    /// DbgEng's connect timeout bounds every other case.
    /// </summary>
    private ToolResult? RequireKdConnectable()
    {
        if (_state.KdConnected)
            return ToolResult.Error(ErrorMessages.KdAlreadyConnected);
        if (_state.VmPower == VmPowerState.Paused)
            return ToolResult.Error("The VM is paused. Call vm_resume first, then kd_connect.");
        if (_state.VmPower == VmPowerState.Saved)
            return ToolResult.Error("The VM is saved. Call vm_start first, then kd_connect.");
        if (_state.VmPower == VmPowerState.Off && _state.VmPowerFromHost)
            return ToolResult.Error("The host reports that the VM is off. Call vm_start first, then kd_connect.");
        return null;
    }

    private ToolResult? RequireKdConnected()
    {
        if (!_state.KdConnected)
            return ToolResult.Error(ErrorMessages.KdNotConnected);
        return null;
    }

    private ToolResult? RequireKdConnected_TargetHalted()
    {
        if (!_state.KdConnected)
            return ToolResult.Error(ErrorMessages.KdNotConnected);
        if (_state.KdExecStatus != DebugExecutionStatus.Break)
            return ToolResult.Error(
                $"The target is in the '{_state.KdExecStatus}' state, so it cannot be inspected or stepped. " +
                "Call kd_break to halt it first, or kd_wait_for_event to wait for a breakpoint.");
        return null;
    }

    private ToolResult? RequireKdConnected_TargetRunning()
    {
        if (!_state.KdConnected)
            return ToolResult.Error(ErrorMessages.KdNotConnected);
        if (_state.KdExecStatus == DebugExecutionStatus.Break)
            return ToolResult.Error(_state.IsBugcheck
                ? ErrorMessages.BsodCannotBreak(_state.BugcheckCode)
                : ErrorMessages.TargetAlreadyBroken);
        return null;
    }

    private ToolResult? RequireKdConnected_TargetHalted_CanResume()
    {
        if (!_state.KdConnected)
            return ToolResult.Error(ErrorMessages.KdNotConnected);
        if (_state.KdExecStatus != DebugExecutionStatus.Break)
            return ToolResult.Error(
                $"The target is in the '{_state.KdExecStatus}' state, so it is already running. " +
                "Call kd_break to halt it, or kd_wait_for_event to wait for a breakpoint.");
        if (_state.IsBugcheck)
            return ToolResult.Error(ErrorMessages.BsodCannotResume(_state.BugcheckCode));
        return null;
    }

    private ToolResult? RequireGuestOpsAvailable()
    {
        // First: is the kernel debugger holding the guest frozen? Then the probe cannot answer either.
        if (_state.KdConnected && _state.KdExecStatus == DebugExecutionStatus.Break)
            return ToolResult.Error(_state.IsBugcheck
                ? ErrorMessages.BsodGuestOpsUnavailable(_state.BugcheckCode)
                : ErrorMessages.GuestFrozenByKd);

        switch (_state.VmPower)
        {
            case VmPowerState.Paused:
                return ToolResult.Error(ErrorMessages.VmIsPaused);
            case VmPowerState.Running:
                break;
            case VmPowerState.Off:
                return ToolResult.Error(ErrorMessages.VmIsOff);
            default:
                return ToolResult.Error(
                    $"The VM is {_state.VmPower}, so guest tools cannot run. Start the VM with vm_start, or call " +
                    "get_system_state(queryHost=true) if it was started outside this server.");
        }

        if (_state.GuestSsh != GuestSshState.Reachable)
            return ToolResult.Error(ErrorMessages.GuestSshNotAnswering);

        return null;
    }
}
