using System.ComponentModel;
using ModelContextProtocol.Protocol.Types;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.Tools;

[McpServerToolType]
public static class GuestTools
{
    [McpServerTool(Name = "guest_run_command", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false), Description(
        "Run a cmd.exe command in the guest over SSH as the configured guest account (normally an administrator) " +
        "and return the exit code, stdout and stderr. Not while the kernel debugger holds the guest halted. " +
        "Examples: 'ipconfig /all', 'sc query MyDriver', 'tasklist', 'taskkill /F /PID 1234'.")]
    public static async Task<CallToolResponse> GuestRunCommand(
        StateCoordinator state,
        GuestExecManager guest,
        ToolOutput output,
        [Description("Command to run (cmd.exe syntax)")] string command,
        [Description("Working directory in the guest (optional)")] string? workingDirectory = null,
        [Description("Timeout in seconds, max 3600 (0: Timeouts.GuestCommandSeconds, 45 by default)")] int timeoutSeconds = 0,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("guest_run_command");
        if (precheck != null) return output.Error("guest_run_command", precheck.Message);

        var result = await guest.RunCommandAsync(command, workingDirectory, timeoutSeconds > 0 ? timeoutSeconds : null, ct);
        return result.Success
            ? output.Ok("guest_run_command", result.ToString())
            : output.Error("guest_run_command", result.ToString());
    }

    [McpServerTool(Name = "guest_transfer_to_vm", ReadOnly = false, Destructive = true, Idempotent = true, OpenWorld = false), Description(
        "Copy a host file to the guest (scp), for example a driver or a test binary. The host path must be inside " +
        "Policy.HostTransferRoots (default %LOCALAPPDATA%\\windbg-hyperv-mcp\\transfer); environment variables in it are expanded.")]
    public static Task<CallToolResponse> GuestTransferToVm(
        StateCoordinator state,
        GuestExecManager guest,
        ToolOutput output,
        [Description("Host file path")] string hostPath,
        [Description("Destination path in the guest")] string guestPath,
        CancellationToken ct = default)
        => TransferAsync("guest_transfer_to_vm", state, output, () => guest.CopyFileToGuestAsync(hostPath, guestPath, ct));

    [McpServerTool(Name = "guest_transfer_from_vm", ReadOnly = false, Destructive = true, Idempotent = true, OpenWorld = false), Description(
        "Copy a guest file to the host (scp), for example a crash dump or a log. The host path must be inside " +
        "Policy.HostTransferRoots (default %LOCALAPPDATA%\\windbg-hyperv-mcp\\transfer); environment variables in it are expanded.")]
    public static Task<CallToolResponse> GuestTransferFromVm(
        StateCoordinator state,
        GuestExecManager guest,
        ToolOutput output,
        [Description("File path in the guest")] string guestPath,
        [Description("Host destination file path")] string hostPath,
        CancellationToken ct = default)
        => TransferAsync("guest_transfer_from_vm", state, output, () => guest.CopyFileFromGuestAsync(guestPath, hostPath, ct));

    private static async Task<CallToolResponse> TransferAsync(string tool, StateCoordinator state, ToolOutput output,
        Func<Task<string>> transfer)
    {
        var precheck = await state.ValidatePreconditionsAsync(tool);
        if (precheck != null) return output.Error(tool, precheck.Message);

        try
        {
            return output.Ok(tool, await transfer());
        }
        catch (HostPathRefusedException ex)
        {
            return output.Error(tool, "REFUSED: " + ex.Message);
        }
        catch (TimeoutException ex)
        {
            return output.Error(tool, ex.Message + " The file may be large, or the guest is not responding. Check get_system_state.");
        }
        catch (OperationCanceledException) { throw; }   // a client cancellation propagates
        catch (Exception ex)
        {
            return output.Error(tool, $"{tool} failed: {ex.Message}");
        }
    }
}
