using System.ComponentModel;
using ModelContextProtocol.Protocol.Types;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.KernelDebug;
using WinDbgMCP.Server.KernelDebug.Interop;
using WinDbgMCP.Server.Security;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.Tools;

/// <summary>Kernel debugging over KDNET (or serial). Not registered when Policy.KernelDebug is Disabled.</summary>
[McpServerToolType]
public static class KernelDebugTools
{
    [McpServerTool(Name = "kd_connect", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false), Description(
        "Attach the kernel debugger to the guest over the configured transport (KernelDebug.*). The guest must boot " +
        "with kernel debugging enabled; it does not need to answer on SSH. The target halts at the initial break.")]
    public static async Task<CallToolResponse> KdConnect(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ServerConfig config,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_connect");
        if (precheck != null) return output.Error("kd_connect", precheck.Message);

        try
        {
            var result = await dbgEng.ConnectKernelAsync();
            state.SetKdConnected(config.KernelDebug.Transport.Equals("serial", StringComparison.OrdinalIgnoreCase)
                ? KdTransport.Serial
                : KdTransport.KDNET);
            return output.Ok("kd_connect", result);
        }
        catch (TimeoutException ex)
        {
            return output.Error("kd_connect",
                $"kd_connect did not complete within {config.Timeouts.KdConnectSeconds} s ({ex.Message}) " +
                ErrorMessages.KdConnectFailed);
        }
        catch (Exception ex)
        {
            return output.Error("kd_connect", $"kd_connect failed: {ex.Message}");
        }
    }

    [McpServerTool(Name = "kd_disconnect", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "Disconnect from the kernel debug target. A halted target is resumed first, so the VM keeps running.")]
    public static async Task<CallToolResponse> KdDisconnect(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_disconnect");
        if (precheck != null) return output.Error("kd_disconnect", precheck.Message);

        try
        {
            var result = await dbgEng.DisconnectAsync();
            state.SetKdDisconnected();
            return output.Ok("kd_disconnect", result);
        }
        catch (Exception ex)
        {
            // Not marked disconnected: the session may still be open.
            return output.Error("kd_disconnect",
                $"kd_disconnect did not complete ({ex.Message}). The session may still be open. Call kd_disconnect " +
                "again; if it fails again, restart the MCP server.");
        }
    }

    [McpServerTool(Name = "kd_break", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "Break into the running target (Ctrl+Break in WinDbg). Then use kd_execute to inspect it.")]
    public static async Task<CallToolResponse> KdBreak(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_break");
        if (precheck != null) return output.Error("kd_break", precheck.Message);

        try
        {
            var result = await dbgEng.BreakAsync();
            return output.Ok("kd_break", result + await BugcheckNoteAsync(state, dbgEng));
        }
        catch (Exception ex)
        {
            return output.Error("kd_break", $"kd_break failed: {ex.Message}");
        }
    }

    [McpServerTool(Name = "kd_continue", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false), Description(
        "Resume the halted target (go). Returns at once. Then call kd_wait_for_event to wait for a breakpoint, or " +
        "kd_break to halt it again. Guest tools need the target running.")]
    public static async Task<CallToolResponse> KdContinue(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ToolOutput output,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_continue");
        if (precheck != null) return output.Error("kd_continue", precheck.Message);

        try
        {
            return output.Ok("kd_continue", await dbgEng.ContinueAsync());
        }
        catch (Exception ex)
        {
            return output.Error("kd_continue", $"kd_continue failed: {ex.Message}");
        }
    }

    [McpServerTool(Name = "kd_step", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false), Description(
        "Step one instruction in the halted target: 'over' steps over calls, 'into' steps into them. " +
        "Returns the new instruction pointer and its disassembly.")]
    public static async Task<CallToolResponse> KdStep(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ToolOutput output,
        [Description("over (default) or into")] StepMode mode = StepMode.Over,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_step");
        if (precheck != null) return output.Error("kd_step", precheck.Message);

        try
        {
            return output.Ok("kd_step", await dbgEng.StepAsync(mode == StepMode.Into));
        }
        catch (Exception ex)
        {
            return output.Error("kd_step", $"kd_step failed: {ex.Message}");
        }
    }

    [McpServerTool(Name = "kd_execute", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false), Description(
        "Run a WinDbg command in the halted target and return its output, for example 'k', 'r', 'lm', " +
        "'!process 0 0', '!analyze -v', 'db <addr>', 'u <addr>', 'bp <symbol>'. Commands that resume the target " +
        "(g, t, p, gu, wt and variants) are refused: use kd_continue and kd_step. Commands that act on the host " +
        "are refused by default; only listed dot-commands run.")]
    public static async Task<CallToolResponse> KdExecute(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ServerConfig config,
        ToolOutput output,
        [Description("WinDbg command")] string command,
        [Description("Timeout in seconds (default 30, max 300)")] int timeoutSeconds = 30,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("kd_execute");
        if (precheck != null) return output.Error("kd_execute", precheck.Message);

        var (isBlocked, blockedCmd, suggestion) = DbgEngConstants.CheckCommand(command);
        if (isBlocked)
            return output.Error("kd_execute",
                $"BLOCKED: '{blockedCmd}' would resume the target or end the session outside kd_continue, kd_step and " +
                $"kd_disconnect, and the server would lose track of the target's state. {suggestion}");

        var hostRefusal = HostCommandGuard.Refusal("kd_execute", command, config.Policy.BlockHostSideEffectCommands);
        if (hostRefusal != null) return output.Error("kd_execute", hostRefusal);

        timeoutSeconds = Math.Clamp(timeoutSeconds, 1, 300);
        try
        {
            return output.Ok("kd_execute", await dbgEng.ExecuteCommandAsync(command, timeoutSeconds));
        }
        catch (DbgEngTimeoutException ex)
        {
            return output.Error("kd_execute", $"'{command}': {ex.Message}");
        }
        catch (Exception ex)
        {
            return output.Error("kd_execute", $"kd_execute failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Upper bound for kd_wait_for_event's timeout. The whole call (wait, plus up to 7 s for the fallback
    /// break-in and DbgEng-thread slack) stays under 60 s, the default request timeout of the MCP TypeScript
    /// SDK that several MCP clients use; a client that stops waiting loses the result.
    /// </summary>
    public const int KdWaitMaxSeconds = 50;

    [McpServerTool(Name = "kd_wait_for_event", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false), Description(
        "Wait for a debug event (breakpoint hit, exception, assertion) after kd_continue. Returns within the timeout; " +
        "with no event the target keeps running and is not interrupted. If the target is already halted, returns at " +
        "once without resuming it.")]
    public static async Task<CallToolResponse> KdWaitForEvent(
        StateCoordinator state,
        DbgEngManager dbgEng,
        ToolOutput output,
        [Description("Seconds to wait (default 10, max 50)")] int timeoutSeconds = 10,
        CancellationToken ct = default)
    {
        // The timeout is end-to-end: time spent in the precondition refresh counts against it.
        var start = DateTime.UtcNow;

        var precheck = await state.ValidatePreconditionsAsync("kd_wait_for_event");
        if (precheck != null) return output.Error("kd_wait_for_event", precheck.Message);

        timeoutSeconds = Math.Clamp(timeoutSeconds, 1, KdWaitMaxSeconds);
        try
        {
            var result = await dbgEng.WaitForEventAsync(timeoutSeconds, start.AddSeconds(timeoutSeconds));
            if (result.Contains("halted", StringComparison.OrdinalIgnoreCase))
                result += await BugcheckNoteAsync(state, dbgEng);
            return output.Ok("kd_wait_for_event", result);
        }
        catch (Exception ex)
        {
            return output.Error("kd_wait_for_event", $"kd_wait_for_event failed: {ex.Message}");
        }
    }

    /// <summary>A note when the halted target is at a bugcheck (and records it in the state), else "".</summary>
    private static async Task<string> BugcheckNoteAsync(StateCoordinator state, DbgEngManager dbgEng)
    {
        try
        {
            var (isBugcheck, code) = await dbgEng.DetectBugcheckAsync();
            if (!isBugcheck) return "";
            state.SetBsodDetected(code);
            return $"\n\nBugcheck {code ?? "(code unknown)"}: the guest OS has crashed. Inspect it with " +
                   "kd_execute('!analyze -v'). Guest tools do not work; recover with vm_stop(turnOff=true) and vm_start.";
        }
        catch
        {
            return "";
        }
    }
}
