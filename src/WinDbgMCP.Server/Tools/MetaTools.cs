using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Protocol.Types;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.Tools;

[McpServerToolType]
public static class MetaTools
{
    [McpServerTool(Name = "get_system_state", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false), Description(
        "State of the VM, the kernel debugger and guest operations. Always allowed; call it when unsure what is " +
        "possible. VM power is inferred from guest SSH reachability; queryHost=true also runs the host Status task " +
        "for the Hyper-V state.")]
    public static async Task<CallToolResponse> GetSystemState(
        StateCoordinator state,
        LabHost lab,
        ToolOutput output,
        [Description("Also ask the host for the Hyper-V state, heartbeat and IPv4 (runs the Status task)")] bool queryHost = false,
        CancellationToken ct = default)
    {
        string? hostLine = null;
        if (queryHost)
        {
            var host = await lab.QueryHostStatusAsync(ct);
            if (host.Host != null)
                state.ApplyHostState(host.Host.StateAfter);
            hostLine = host.Message;
        }

        await state.RefreshStateAsync();
        return output.Ok("get_system_state", Format(state.State, hostLine));
    }

    internal static string Format(SystemState s, string? hostLine)
    {
        var sb = new StringBuilder();
        if (hostLine != null)
            sb.AppendLine($"Host (Hyper-V):       {hostLine}");

        sb.AppendLine($"VM:                   {s.VmName} ({s.VmIpAddress ?? "no address"})");
        sb.AppendLine($"VM power:             {s.VmPower}" + (s.VmPowerFromHost
            ? "  (reported by the host or a vm_* tool)"
            : "  (inferred from guest SSH reachability: Off also covers paused, booting and no network)"));
        sb.AppendLine($"Guest SSH:            {s.GuestSsh}");

        if (s.KdConnected)
        {
            sb.AppendLine($"Kernel debugger:      connected over {s.KdTransportType}, target {s.KdExecStatus}");
            if (s.KdExecStatus == DebugExecutionStatus.Break && s.IsBugcheck)
                sb.AppendLine($"Bugcheck:             {s.BugcheckCode ?? "(code unknown)"}. The guest OS crashed; guest tools do not work. " +
                              "Run kd_execute('!analyze -v'), then vm_stop(turnOff=true) and vm_start.");
            sb.AppendLine($"Queued debug events:  {s.PendingEventCount}");
        }
        else
        {
            sb.AppendLine("Kernel debugger:      not connected");
        }

        sb.Append("Guest tools:          ");
        if (s.GuestOpsAvailable)
            sb.AppendLine("available");
        else if (s.KdConnected && s.KdExecStatus == DebugExecutionStatus.Break)
            sb.AppendLine(s.IsBugcheck ? "not available (bugcheck)" : "not available (the kernel debugger holds the guest halted; call kd_continue)");
        else if (s.VmPower != VmPowerState.Running)
            sb.AppendLine($"not available (VM power {s.VmPower})");
        else
            sb.AppendLine($"not available (guest SSH {s.GuestSsh})");

        if (s.FridaBackgroundTarget != null)
            sb.AppendLine($"Frida background:     running on {s.FridaBackgroundTarget}");

        return sb.ToString();
    }
}
