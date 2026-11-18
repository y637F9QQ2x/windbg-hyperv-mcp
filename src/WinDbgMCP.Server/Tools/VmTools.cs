using System.ComponentModel;
using ModelContextProtocol.Protocol.Types;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.KernelDebug;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.Tools;

/// <summary>VM lifecycle. Each tool runs one lab task of the host automation (\HyperVLpeLab\&lt;Lab&gt;\&lt;Action&gt;).</summary>
[McpServerToolType]
public static class VmTools
{
    [McpServerTool(Name = "vm_start", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "Start the VM (runs the host Start task). Allowed when the guest is not reachable. " +
        "Guest tools work once get_system_state shows Guest SSH reachable.")]
    public static async Task<CallToolResponse> VmStart(
        StateCoordinator state,
        LabHost lab,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("vm_start");
        if (precheck != null) return output.Error("vm_start", precheck.Message);

        var result = await lab.StartAsync(ct);
        if (!result.Success)
            return output.Error("vm_start", $"vm_start failed: {result.Message}");

        state.ApplyHostState(result.Host?.StateAfter);
        return output.Ok("vm_start", result.Message + " Call get_system_state to see when the guest is reachable.");
    }

    [McpServerTool(Name = "vm_stop", ReadOnly = false, Destructive = true, Idempotent = true, OpenWorld = false), Description(
        "Stop the VM: a guest shutdown (host Stop task), or with turnOff=true a power-off (host TurnOff task, " +
        "also works on a hung or crashed guest). Ends the kernel debug session and a Frida background session.")]
    public static async Task<CallToolResponse> VmStop(
        StateCoordinator state,
        LabHost lab,
        DbgEngManager dbgEng,
        ToolOutput output,
        [Description("true: cut power instead of asking the guest to shut down")] bool turnOff = false,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("vm_stop");
        // The vm_stop precheck returns Success with a warning when KD is attached.
        if (precheck != null && !precheck.IsSuccess) return output.Error("vm_stop", precheck.Message);
        var warning = precheck?.IsSuccess == true ? precheck.Message + " " : "";

        // End the DbgEng/KDNET session cleanly before the guest goes away.
        if (state.State.KdConnected)
        {
            try
            {
                await dbgEng.DisconnectAsync();
                state.SetKdDisconnected();
            }
            catch (Exception ex)
            {
                warning += $"The kernel debug session did not close cleanly ({ex.Message}); it is reset after the stop. ";
            }
        }

        var result = await lab.StopAsync(turnOff, ct);
        if (!result.Success)
            return output.Error("vm_stop", $"{warning}vm_stop failed: {result.Message}");

        if (!result.IsPending)
            await state.ResetAfterStopAsync();   // the guest is gone: every session with it is too
        return output.Ok("vm_stop", warning + result.Message);
    }

    [McpServerTool(Name = "vm_pause", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "Pause the VM (runs the host Pause task). Everything freezes: guest, network and kernel debugger. " +
        "Not the same as kd_break. Use vm_resume to continue.")]
    public static async Task<CallToolResponse> VmPause(
        StateCoordinator state,
        LabHost lab,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("vm_pause");
        if (precheck != null && !precheck.IsSuccess) return output.Error("vm_pause", precheck.Message);
        var warning = precheck?.IsSuccess == true ? precheck.Message + " " : "";

        var result = await lab.PauseAsync(ct);
        if (!result.Success)
            return output.Error("vm_pause", $"vm_pause failed: {result.Message}");

        if (!result.IsPending)
            state.SetVmPaused();
        return output.Ok("vm_pause", warning + result.Message);
    }

    [McpServerTool(Name = "vm_resume", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "Resume a VM that vm_pause paused (runs the host Resume task).")]
    public static async Task<CallToolResponse> VmResume(
        StateCoordinator state,
        LabHost lab,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("vm_resume");
        if (precheck != null) return output.Error("vm_resume", precheck.Message);

        var result = await lab.ResumeAsync(ct);
        if (!result.Success)
            return output.Error("vm_resume", $"vm_resume failed: {result.Message}");

        if (!result.IsPending)
            state.SetVmResumed();
        return output.Ok("vm_resume", result.Message);
    }
}
