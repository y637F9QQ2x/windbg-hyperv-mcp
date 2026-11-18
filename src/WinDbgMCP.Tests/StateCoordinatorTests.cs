using Microsoft.Extensions.Logging.Abstractions;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Tests;

/// <summary>
/// Tests the precondition gate for every tool, and the state the one SSH probe per refresh produces.
/// </summary>
public class StateCoordinatorTests
{
    private readonly StateCoordinator _coordinator;

    // Controllable state returned by the delegates
    private bool _sshReachable = true;
    private int _probes;
    private DebugExecutionStatus _execStatus = DebugExecutionStatus.NoDebuggee;
    private bool _dbgEngConnected;
    private string? _fridaBackground;

    public StateCoordinatorTests()
    {
        var config = new ServerConfig
        {
            Vm = new VmConfig { VmName = "TestVM" },
            Timeouts = new TimeoutConfig { VmStateQuerySeconds = 5 },
        };

        _coordinator = new StateCoordinator(config, NullLogger<StateCoordinator>.Instance)
        {
            ProbeInterval = TimeSpan.Zero,   // probe on every refresh
            ProbeGuestSshAsync = () => { _probes++; return Task.FromResult(_sshReachable); },
            IsDbgEngConnected = () => _dbgEngConnected,
            GetDbgEngExecutionStatus = () => _execStatus,
            GetPendingEventCount = () => 0,
            GetFridaBackgroundTarget = () => _fridaBackground,
        };
    }

    // ===============================================================
    //  HELPERS
    // ===============================================================

    private void SetVmOff() => _sshReachable = false;

    private void SetVmRunning() => _sshReachable = true;

    private void SetKdConnectedHalted()
    {
        _dbgEngConnected = true;
        _execStatus = DebugExecutionStatus.Break;
        _coordinator.SetKdConnected(KdTransport.KDNET);
    }

    private void SetKdConnectedRunning()
    {
        _dbgEngConnected = true;
        _execStatus = DebugExecutionStatus.Go;
        _coordinator.SetKdConnected(KdTransport.KDNET);
        _coordinator.State.KdExecStatus = DebugExecutionStatus.Go;
    }

    // ===============================================================
    //  ONE PROBE PER REFRESH
    // ===============================================================

    [Fact]
    public async Task Refresh_ProbesOnceAndSetsPowerAndSsh()
    {
        await _coordinator.RefreshStateAsync();
        Assert.Equal(1, _probes);
        Assert.Equal(VmPowerState.Running, _coordinator.State.VmPower);
        Assert.Equal(GuestSshState.Reachable, _coordinator.State.GuestSsh);
        Assert.False(_coordinator.State.VmPowerFromHost);
        Assert.True(_coordinator.State.GuestOpsAvailable);
    }

    [Fact]
    public async Task RunningVm_TurnsOffOnlyAfterTwoFailedProbes()
    {
        await _coordinator.RefreshStateAsync();
        SetVmOff();

        await _coordinator.RefreshStateAsync();
        Assert.Equal(VmPowerState.Running, _coordinator.State.VmPower);
        Assert.Equal(GuestSshState.Unreachable, _coordinator.State.GuestSsh);
        Assert.False(_coordinator.State.GuestOpsAvailable);
        Assert.Contains("SSH", (await _coordinator.ValidatePreconditionsAsync("guest_run_command"))!.Message);

        await _coordinator.RefreshStateAsync();
        Assert.Equal(VmPowerState.Off, _coordinator.State.VmPower);
    }

    [Fact]
    public async Task ProbeInterval_LimitsProbes()
    {
        _coordinator.ProbeInterval = TimeSpan.FromHours(1);
        await _coordinator.RefreshStateAsync();
        await _coordinator.RefreshStateAsync();
        Assert.Equal(1, _probes);
    }

    // ===============================================================
    //  VM TOOLS
    // ===============================================================

    [Fact]
    public async Task VmStart_AllowedWhenGuestUnreachable()
    {
        SetVmOff();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_start"));
    }

    [Fact]
    public async Task VmStart_FailsWhenVmRunning()
    {
        SetVmRunning();
        var result = await _coordinator.ValidatePreconditionsAsync("vm_start");
        Assert.NotNull(result);
        Assert.False(result!.IsSuccess);
        Assert.Contains("vm_stop", result.Message);
    }

    [Fact]
    public async Task VmStop_AllowedWhetherOrNotTheGuestAnswers()
    {
        // An unreachable guest may be hung; the host task knows the real state (TurnOff works in any state).
        SetVmRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_stop"));
        SetVmOff();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_stop"));
    }

    [Fact]
    public async Task VmStop_WarnsWhenKdAttached()
    {
        SetKdConnectedHalted();
        var result = await _coordinator.ValidatePreconditionsAsync("vm_stop");
        Assert.NotNull(result);
        Assert.True(result!.IsSuccess); // warning, not error
        Assert.Contains("WARNING", result.Message);
    }

    [Fact]
    public async Task VmPause_RequiresVmRunning()
    {
        SetVmRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_pause"));
        SetVmOff();
        _coordinator.ApplyHostState("Off");
        Assert.False((await _coordinator.ValidatePreconditionsAsync("vm_pause"))!.IsSuccess);
    }

    [Fact]
    public async Task VmResume_RequiresVmPaused()
    {
        SetVmRunning();
        Assert.NotNull(await _coordinator.ValidatePreconditionsAsync("vm_resume"));
        _coordinator.SetVmPaused();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_resume"));
    }

    [Theory]
    [InlineData("Running", VmPowerState.Running)]
    [InlineData("Off", VmPowerState.Off)]
    [InlineData("Paused", VmPowerState.Paused)]
    [InlineData("Saved", VmPowerState.Saved)]
    public void ApplyHostState_MapsHyperVStates(string hyperV, VmPowerState expected)
    {
        _coordinator.ApplyHostState(hyperV);
        Assert.Equal(expected, _coordinator.State.VmPower);
        Assert.True(_coordinator.State.VmPowerFromHost);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Starting")]
    [InlineData("Stopping")]
    public void ApplyHostState_IgnoresTransitionalStates(string? hyperV)
    {
        _coordinator.State.VmPower = VmPowerState.Running;
        _coordinator.ApplyHostState(hyperV);
        Assert.Equal(VmPowerState.Running, _coordinator.State.VmPower);
    }

    [Fact]
    public async Task HostReportedPause_LetsVmResumeThrough()
    {
        // A VM paused outside this server reads Off on the SSH probe; the host Status result fixes that.
        SetVmOff();
        Assert.NotNull(await _coordinator.ValidatePreconditionsAsync("vm_resume"));
        _coordinator.ApplyHostState("Paused");
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("vm_resume"));
        Assert.Equal(VmPowerState.Paused, _coordinator.State.VmPower);   // not re-probed while paused
    }

    // ===============================================================
    //  KERNEL DEBUG TOOLS
    // ===============================================================

    [Fact]
    public async Task KdConnect_AllowedWhenTheGuestAnswersOnSsh()
    {
        SetVmRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_connect"));
    }

    [Fact]
    public async Task KdConnect_AllowedWhenOnlyTheSshProbeSaysOff()
    {
        // A guest that is booting, hung in user mode or without sshd still answers KDNET.
        SetVmOff();
        await _coordinator.RefreshStateAsync();
        Assert.Equal(VmPowerState.Off, _coordinator.State.VmPower);
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_connect"));
    }

    [Theory]
    [InlineData("Off", "vm_start")]
    [InlineData("Paused", "vm_resume")]
    [InlineData("Saved", "vm_start")]
    public async Task KdConnect_RefusedWhenTheHostReportsTheVmIsNotRunning(string hyperV, string next)
    {
        SetVmOff();
        _coordinator.ApplyHostState(hyperV);
        var result = await _coordinator.ValidatePreconditionsAsync("kd_connect");
        Assert.NotNull(result);
        Assert.Contains(next, result!.Message);
    }

    [Fact]
    public async Task KdConnect_FailsWhenAlreadyConnected()
    {
        SetKdConnectedHalted();
        var result = await _coordinator.ValidatePreconditionsAsync("kd_connect");
        Assert.NotNull(result);
        Assert.Contains("already connected", result!.Message);
    }

    [Fact]
    public async Task KdDisconnectAndWait_RequireKdConnected()
    {
        Assert.Contains("not connected", (await _coordinator.ValidatePreconditionsAsync("kd_disconnect"))!.Message);
        Assert.NotNull(await _coordinator.ValidatePreconditionsAsync("kd_wait_for_event"));
        SetKdConnectedHalted();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_disconnect"));
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_wait_for_event"));
    }

    [Fact]
    public async Task KdBreak_RequiresARunningTarget()
    {
        SetKdConnectedRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_break"));
    }

    [Fact]
    public async Task KdBreak_FailsWhenTargetAlreadyHalted()
    {
        SetKdConnectedHalted();
        Assert.Contains("already halted", (await _coordinator.ValidatePreconditionsAsync("kd_break"))!.Message);
    }

    [Fact]
    public async Task KdBreak_ExplainsABugcheck()
    {
        SetKdConnectedHalted();
        _coordinator.SetBsodDetected("0x0000007E");
        Assert.Contains("Bugcheck", (await _coordinator.ValidatePreconditionsAsync("kd_break"))!.Message);
    }

    [Fact]
    public async Task KdContinue_RequiresAHaltedTarget()
    {
        SetKdConnectedHalted();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("kd_continue"));
    }

    [Fact]
    public async Task KdContinue_FailsWhenTargetRunning()
    {
        SetKdConnectedRunning();
        Assert.Contains("already running", (await _coordinator.ValidatePreconditionsAsync("kd_continue"))!.Message);
    }

    [Fact]
    public async Task KdContinue_FailsOnBugcheck()
    {
        SetKdConnectedHalted();
        _coordinator.SetBsodDetected("0x0000007E");
        var result = await _coordinator.ValidatePreconditionsAsync("kd_continue");
        Assert.NotNull(result);
        Assert.Contains("Bugcheck", result!.Message);
        Assert.Contains("!analyze", result.Message);
    }

    [Theory]
    [InlineData("kd_step")]
    [InlineData("kd_execute")]
    public async Task KdStepAndExecute_RequireAHaltedTarget(string tool)
    {
        SetKdConnectedHalted();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync(tool));
        SetKdConnectedRunning();
        Assert.Contains("kd_break", (await _coordinator.ValidatePreconditionsAsync(tool))!.Message);
    }

    // ===============================================================
    //  GUEST AND USER-MODE TOOLS
    // ===============================================================

    [Theory]
    [InlineData("guest_run_command")]
    [InlineData("guest_transfer_to_vm")]
    [InlineData("guest_transfer_from_vm")]
    [InlineData("umd_frida")]
    [InlineData("umd_dbgsrv")]
    [InlineData("umd_ttd")]
    public async Task GuestTools_NeedAnAnsweringGuest(string tool)
    {
        SetVmRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync(tool));
    }

    [Theory]
    [InlineData("guest_run_command")]
    [InlineData("umd_frida")]
    public async Task GuestTools_FailWhenVmOff(string tool)
    {
        SetVmOff();
        var result = await _coordinator.ValidatePreconditionsAsync(tool);
        Assert.NotNull(result);
        Assert.False(result!.IsSuccess);
        Assert.Contains("vm_start", result.Message);
    }

    [Theory]
    [InlineData("guest_run_command")]
    [InlineData("umd_dbgsrv")]
    public async Task GuestTools_FailWhenKdFrozen(string tool)
    {
        SetVmRunning();
        await _coordinator.RefreshStateAsync();
        SetKdConnectedHalted();
        Assert.Contains("kd_continue", (await _coordinator.ValidatePreconditionsAsync(tool))!.Message);
    }

    [Fact]
    public async Task GuestTools_FailWhenVmPaused()
    {
        SetVmRunning();
        _coordinator.SetVmPaused();
        Assert.Contains("vm_resume", (await _coordinator.ValidatePreconditionsAsync("guest_run_command"))!.Message);
    }

    [Fact]
    public async Task GuestTools_BugcheckBlocksWithSpecificMessage()
    {
        SetKdConnectedHalted();
        _coordinator.SetBsodDetected("0x0000007E");
        var result = await _coordinator.ValidatePreconditionsAsync("guest_run_command");
        Assert.NotNull(result);
        Assert.Contains("Bugcheck", result!.Message);
        Assert.Contains("crashed", result.Message);
    }

    // ===============================================================
    //  META
    // ===============================================================

    [Fact]
    public async Task GetSystemState_AlwaysAllowed()
    {
        SetVmOff();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("get_system_state"));
        SetVmRunning();
        Assert.Null(await _coordinator.ValidatePreconditionsAsync("get_system_state"));
    }

    [Fact]
    public async Task UnknownToolName_FailsClosed()
    {
        var result = await _coordinator.ValidatePreconditionsAsync("some_unknown_tool");
        Assert.NotNull(result);
        Assert.False(result!.IsSuccess);
    }

    // ===============================================================
    //  STATE TRANSITIONS
    // ===============================================================

    [Fact]
    public void SetKdConnected_SetsCorrectState()
    {
        _coordinator.SetKdConnected(KdTransport.KDNET);
        var state = _coordinator.State;
        Assert.True(state.KdConnected);
        Assert.Equal(KdTransport.KDNET, state.KdTransportType);
        Assert.Equal(DebugExecutionStatus.Break, state.KdExecStatus);
    }

    [Fact]
    public void SetKdDisconnected_ClearsAllKdState()
    {
        _coordinator.SetKdConnected(KdTransport.KDNET);
        _coordinator.SetBsodDetected("0x7E");

        _coordinator.SetKdDisconnected();
        var state = _coordinator.State;
        Assert.False(state.KdConnected);
        Assert.Equal(KdTransport.None, state.KdTransportType);
        Assert.Equal(DebugExecutionStatus.NoDebuggee, state.KdExecStatus);
        Assert.False(state.IsBugcheck);
        Assert.Null(state.BugcheckCode);
    }

    [Fact]
    public async Task ResetAfterStop_ClearsEverythingAndRunsTheCleanups()
    {
        SetKdConnectedHalted();
        _coordinator.SetBsodDetected("0x7E");

        bool kdCleaned = false, fridaCleaned = false;
        _coordinator.CleanupKdSessionAsync = () => { kdCleaned = true; return Task.CompletedTask; };
        _coordinator.CleanupFridaSession = () => fridaCleaned = true;

        await _coordinator.ResetAfterStopAsync();

        Assert.True(kdCleaned);
        Assert.True(fridaCleaned);
        var state = _coordinator.State;
        Assert.False(state.KdConnected);
        Assert.Equal(VmPowerState.Off, state.VmPower);
        Assert.True(state.VmPowerFromHost);
        Assert.Equal(GuestSshState.Unknown, state.GuestSsh);
        Assert.False(state.IsBugcheck);
    }

    [Fact]
    public async Task Refresh_DetectsConnectionLoss()
    {
        SetKdConnectedHalted();
        _execStatus = DebugExecutionStatus.NoDebuggee;   // DbgEng reports no debuggee: the session ended
        await _coordinator.RefreshStateAsync();
        Assert.False(_coordinator.State.KdConnected);
    }

    [Fact]
    public async Task Refresh_DetectsADroppedClient()
    {
        SetKdConnectedHalted();
        _dbgEngConnected = false;
        await _coordinator.RefreshStateAsync();
        Assert.False(_coordinator.State.KdConnected);
    }

    [Fact]
    public async Task Refresh_ReportsTheFridaBackgroundSession()
    {
        _fridaBackground = "PID 1234";
        await _coordinator.RefreshStateAsync();
        Assert.Equal("PID 1234", _coordinator.State.FridaBackgroundTarget);
    }

    // Regression: a Set* mutator must be serialized against RefreshStateCore's commit. RefreshStateCore holds
    // _lock across its awaited probe (it yields mid-refresh). An unlocked SetVmPaused running during that yield
    // would be overwritten when the refresh commits the probe result: a paused VM would read Off and vm_resume
    // would be refused. SetVmPaused takes _lock, so it runs after the refresh and the Paused write wins.
    [Fact]
    public async Task SetVmPaused_IsNotOverwrittenBy_ConcurrentRefreshProbe()
    {
        var probeEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseProbe = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _coordinator.ProbeGuestSshAsync = async () =>
        {
            probeEntered.TrySetResult();      // the refresh is inside the probe, holding _lock
            await releaseProbe.Task;          // hold the lock (via the refresh) until the test releases it
            return false;                     // the probe reports the guest unreachable
        };

        var refreshTask = _coordinator.RefreshStateAsync();
        await probeEntered.Task;

        // Concurrently pause. This blocks on _lock (held by the refresh) and runs only after the refresh commits
        // and releases it, so its Paused write is the one that stays.
        var pauseTask = Task.Run(() => _coordinator.SetVmPaused());

        releaseProbe.SetResult();
        await refreshTask;
        await pauseTask;

        Assert.Equal(VmPowerState.Paused, _coordinator.State.VmPower);
    }

    // A KD-halted guest cannot answer the SSH probe: probing it would only cost VmStateQuerySeconds on every
    // kd_* call (pushing kd_wait_for_event past the client's request timeout) and demote Running to Off.
    [Fact]
    public async Task Refresh_SkipsTheProbe_WhileKdHalted_KeepsRunning()
    {
        await _coordinator.RefreshStateAsync();   // Running
        SetKdConnectedHalted();
        SetVmOff();
        var before = _probes;

        await _coordinator.RefreshStateAsync();

        Assert.Equal(before, _probes);
        Assert.Equal(VmPowerState.Running, _coordinator.State.VmPower);
    }

    [Fact]
    public async Task Refresh_StillProbes_WhileKdTargetRunning()
    {
        SetKdConnectedRunning();
        await _coordinator.RefreshStateAsync();
        Assert.Equal(1, _probes);
    }

    [Fact]
    public async Task Refresh_StillProbes_WhenKdHaltedButPowerNotKnownRunning()
    {
        SetKdConnectedHalted();   // VmPower is still Unknown: only a known-Running VM skips the probe
        await _coordinator.RefreshStateAsync();
        Assert.Equal(1, _probes);
        Assert.Equal(VmPowerState.Running, _coordinator.State.VmPower);
    }

    [Fact]
    public void KdWaitMaxSeconds_FitsInsideClientRequestTimeout()
    {
        // The wait, plus 2 s for the fallback break-in and 5 s of DbgEng-thread slack, stays under 60 s.
        Assert.True(WinDbgMCP.Server.Tools.KernelDebugTools.KdWaitMaxSeconds + 2 + 5 < 60);
    }
}
