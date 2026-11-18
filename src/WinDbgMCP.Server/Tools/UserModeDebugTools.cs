using System.ComponentModel;
using ModelContextProtocol.Protocol.Types;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.Security;
using WinDbgMCP.Server.State;
using WinDbgMCP.Server.UserModeDebug;

namespace WinDbgMCP.Server.Tools;

/// <summary>Frida hooks in guest processes. Registered when Tools.Frida is true.</summary>
[McpServerToolType]
public static class FridaTools
{
    [McpServerTool(Name = "umd_frida", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false), Description(
        "Frida in a guest process, by pid or processName: 'eval' runs one JavaScript expression; 'inject' runs a " +
        "script for timeoutSeconds (eternalize=true keeps its hooks); 'inject_bg' runs a script until 'stop_bg', " +
        "and 'collect_bg' returns its output. 'list' lists guest processes, 'start_server' starts frida-server in " +
        "the guest, 'help' returns setup steps and patterns.")]
    public static async Task<CallToolResponse> UmdFrida(
        StateCoordinator state,
        FridaManager frida,
        GuestExecManager guest,
        ServerConfig config,
        ToolOutput output,
        [Description("What to do")] FridaAction action,
        [Description("Target process ID (eval, inject, inject_bg); 0: use processName")] int pid = 0,
        [Description("Target process name, when no pid is given")] string? processName = null,
        [Description("JavaScript: one expression for eval, a script for inject and inject_bg")] string? code = null,
        [Description("Seconds an eval or inject may run (default 30, max 3600)")] int timeoutSeconds = 30,
        [Description("inject: keep the hooks after the call, until the target exits")] bool eternalize = false,
        CancellationToken ct = default)
    {
        // collect_bg, stop_bg and help work in any state.
        switch (action)
        {
            case FridaAction.Help:
                return output.Ok("umd_frida", HelpText(config));
            case FridaAction.CollectBg:
                return Result(output, frida.CollectBackground());
            case FridaAction.StopBg:
                return Result(output, frida.StopBackground());
        }

        var precheck = await state.ValidatePreconditionsAsync("umd_frida");
        if (precheck != null) return output.Error("umd_frida", precheck.Message);

        if (action is FridaAction.Eval or FridaAction.Inject or FridaAction.InjectBg)
        {
            if (pid < 0)
                return output.Error("umd_frida", "pid must be a positive process ID.");
            if (pid == 0 && string.IsNullOrWhiteSpace(processName))
                return output.Error("umd_frida", "Give the target as pid or processName. umd_frida(action='list') lists the guest processes.");
            if (string.IsNullOrEmpty(code))
                return output.Error("umd_frida", action == FridaAction.Eval
                    ? "Give 'code' with the JavaScript expression to evaluate."
                    : "Give 'code' with the JavaScript to run.");
        }

        int? targetPid = pid > 0 ? pid : null;
        var targetName = pid > 0 ? null : processName;
        try
        {
            switch (action)
            {
                case FridaAction.Eval:
                    return Result(output, await frida.EvalAsync(targetPid, targetName, code!, timeoutSeconds, ct));
                case FridaAction.Inject:
                    return Result(output, await frida.InjectAsync(targetPid, targetName, code!, timeoutSeconds, eternalize, ct));
                case FridaAction.InjectBg:
                    return Result(output, await frida.StartBackgroundAsync(targetPid, targetName, code!, ct));
                case FridaAction.List:
                    return Result(output, await frida.ListProcessesAsync(ct));
                case FridaAction.StartServer:
                {
                    var commandLine = FridaManager.BuildServerCommandLine(config.Guest.FridaServerPath,
                        config.Vm.GuestIpAddress, config.Guest.FridaPort, config.Guest.FridaToken);
                    var r = await guest.StartDetachedAsync(commandLine, ct, Redact.CommandLine(commandLine));
                    // A failing PowerShell call can echo its script, and with it the token, on stderr.
                    var text = Redact.CommandLine(r.ToString()) + "\nCall umd_frida(action='list') to check that frida-server answers.";
                    return r.Success && r.ExitCode == 0 && r.Stdout.Contains("ReturnValue=0", StringComparison.Ordinal)
                        ? output.Ok("umd_frida", text)
                        : output.Error("umd_frida", text + $"\nCheck that frida-server exists at {config.Guest.FridaServerPath} in the guest (Guest.FridaServerPath).");
                }
                default:
                    return output.Error("umd_frida", $"Unknown action '{action}'.");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return output.Error("umd_frida", $"umd_frida {action} failed: {ex.Message}");
        }
    }

    private static CallToolResponse Result(ToolOutput output, FridaResult r) =>
        r.Success ? output.Ok("umd_frida", r.Output) : output.Error("umd_frida", r.Output);

    internal static string HelpText(ServerConfig config)
    {
        var server = config.Guest.FridaServerPath;
        var port = config.Guest.FridaPort;
        var ip = config.Vm.GuestIpAddress;
        var token = string.IsNullOrEmpty(config.Guest.FridaToken)
            ? "  frida-server accepts any client that reaches the port: set Guest.FridaToken so it needs a token.\n"
            : "  frida-server is started with --token (Guest.FridaToken); frida.exe gets the same token in FRIDA_TOKEN.\n";

        return $$"""
            FRIDA: QUICK REFERENCE

            SETUP
              Host: frida-tools (pip install frida-tools). The server uses Host.FridaToolsPath, else the first
              PATH entry that has frida.exe. The frida-tools version must match the frida-server version.
              Guest: frida-server at {{server}}. Start it bound to the guest address {{ip}}:{{port}}:
                umd_frida(action="start_server")
              It runs outside the SSH session (WMI Win32_Process.Create), so it keeps running after the call.
            {{token}}  Allow the port in the guest firewall from the host address only:
                netsh advfirewall firewall add rule name=frida dir=in action=allow protocol=TCP localport={{port}} remoteip=<host-ip>

            SESSION MODEL (how long hooks live)
              Each eval or inject starts a new frida.exe on the host. When it exits, its hooks are removed and the
              original code bytes are restored. So:
              - hooks from 'inject' last for timeoutSeconds; hooks from 'eval' last about one second
              - a later eval that reads hooked bytes sees the original bytes
              To keep hooks:
              1. action="inject", eternalize=true: the agent stays loaded until the target exits (it cannot be
                 unloaded; restart the target to remove it).
              2. action="inject_bg": runs until action="stop_bg". Read its output with action="collect_bg".

            WORKFLOW
              umd_frida(action="list")
              umd_frida(action="eval", processName="target.exe", code="Process.enumerateModules().map(m=>m.name)")
              umd_frida(action="inject", pid=1234, code="<script>")

            USEFUL EXPRESSIONS
              Process.id, Process.arch
              Process.getModuleByName('ntdll.dll').base
              Process.getModuleByName('kernel32.dll').getExportByName('CreateFileW')
              ptr('0x7ff612340000').readByteArray(16)

            HOOK PATTERN (with eternalize=true or inject_bg)
              var m = Process.getModuleByName('kernel32.dll');
              Interceptor.attach(m.getExportByName('CreateFileW'), {
                onEnter(args) { console.log('CreateFileW: ' + args[0].readUtf16String()); }
              });

            PITFALLS
              - Frida hides its own trampolines from script memory reads: readU8() on a hooked address returns the
                original bytes. Check that the callback fires instead.
              - frida matches processName without regard to case and refuses a name that matches more than one
                process; then give pid. Use action="list" first.
              - Output comes from console.log(). A script that logs nothing returns nothing.
              - Frida 17 API: Process.getModuleByName('x').getExportByName('y'), not Module.findExportByName('x', 'y').

            TROUBLESHOOTING
              "frida.exe was not found": install frida-tools on the host, or set Host.FridaToolsPath.
              "Failed to connect to remote frida-server": start it (above), check the guest firewall rule, and
                check that Guest.FridaToken matches the token frida-server was started with.
            """;
    }
}

/// <summary>Noninvasive inspection through dbgsrv in the guest. Registered when Tools.Dbgsrv is true.</summary>
[McpServerToolType]
public static class DbgsrvTools
{
    [McpServerTool(Name = "umd_dbgsrv", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false), Description(
        "Inspect guest process pid through dbgsrv: 'command' runs a WinDbg command in a fresh cdb.exe on the host " +
        "that attaches noninvasively (no breakpoints; the target's threads are suspended while the command runs). " +
        "'start_server' starts dbgsrv in the guest; 'help' returns setup steps and useful commands. Commands that " +
        "act on the host are refused by default.")]
    public static async Task<CallToolResponse> UmdDbgsrv(
        StateCoordinator state,
        DbgsrvManager dbgsrv,
        GuestExecManager guest,
        ServerConfig config,
        ToolOutput output,
        [Description("What to do")] DbgsrvAction action,
        [Description("command: guest process ID")] uint pid = 0,
        [Description("command: WinDbg command, for example 'lm', '!peb', '~*k' (no double quotes)")] string? command = null,
        [Description("command: timeout in seconds (default 30, max 600)")] int timeoutSeconds = 30,
        CancellationToken ct = default)
    {
        if (action == DbgsrvAction.Help)
            return output.Ok("umd_dbgsrv", HelpText(config));

        var precheck = await state.ValidatePreconditionsAsync("umd_dbgsrv");
        if (precheck != null) return output.Error("umd_dbgsrv", precheck.Message);

        try
        {
            if (action == DbgsrvAction.StartServer)
            {
                var commandLine = DbgsrvManager.BuildServerCommandLine(config.Guest.DbgsrvPath, config.Guest.DbgsrvPort,
                    config.Guest.DbgsrvPassword);
                var r = await guest.StartDetachedAsync(commandLine, ct, Redact.CommandLine(commandLine));
                // A failing PowerShell call can echo its script, and with it the password, on stderr.
                var text = Redact.CommandLine(r.ToString()) + "\nThen run umd_dbgsrv(action='command', pid=<pid>, command='lm') to check it.";
                return r.Success && r.ExitCode == 0 && r.Stdout.Contains("ReturnValue=0", StringComparison.Ordinal)
                    ? output.Ok("umd_dbgsrv", text)
                    : output.Error("umd_dbgsrv", text + $"\nCheck that dbgsrv.exe exists at {config.Guest.DbgsrvPath} in the guest (Guest.DbgsrvPath).");
            }

            if (pid == 0)
                return output.Error("umd_dbgsrv", "Give 'pid', the guest process to inspect. guest_run_command('tasklist') lists them.");
            if (string.IsNullOrWhiteSpace(command))
                return output.Error("umd_dbgsrv", "Give 'command', the WinDbg command to run.");

            var hostRefusal = HostCommandGuard.Refusal("umd_dbgsrv", command, config.Policy.BlockHostSideEffectCommands);
            if (hostRefusal != null) return output.Error("umd_dbgsrv", hostRefusal);

            var result = await dbgsrv.ExecuteAsync(pid, command, timeoutSeconds, ct);
            return result.Success ? output.Ok("umd_dbgsrv", result.Output) : output.Error("umd_dbgsrv", result.Output);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return output.Error("umd_dbgsrv", $"umd_dbgsrv {action} failed: {ex.Message}");
        }
    }

    internal static string HelpText(ServerConfig config)
    {
        var path = config.Guest.DbgsrvPath;
        var dir = Path.GetDirectoryName(path) ?? path;
        var port = config.Guest.DbgsrvPort;
        var password = string.IsNullOrEmpty(config.Guest.DbgsrvPassword)
            ? "  dbgsrv accepts any client that reaches the port: set Guest.DbgsrvPassword so it needs a password.\n" +
              "  (The tcp transport sends the password unencrypted; Microsoft documents that it gives little protection.)\n"
            : "  dbgsrv is started with password= (Guest.DbgsrvPassword); cdb.exe sends it. The tcp transport sends it\n" +
              "  unencrypted, so it keeps out other machines on the switch, not an eavesdropper.\n";

        return $"""
            DBGSRV: QUICK REFERENCE

            SETUP
              Guest: {path} with dbgeng.dll and dbghelp.dll from the same Debugging Tools build in the same
              folder ({dir}). Without them dbgsrv starts but connections fail with 0x8004010C.
              Start it:
                umd_dbgsrv(action="start_server")
              It runs outside the SSH session (WMI Win32_Process.Create), so it keeps running after the call.
            {password}  Allow the port in the guest firewall from the host address only:
                netsh advfirewall firewall add rule name=dbgsrv dir=in action=allow protocol=TCP localport={port} remoteip=<host-ip>
              Host: cdb.exe from Debugging Tools for Windows (Host.DebuggersPath, or the Windows SDK folder).

            WORKFLOW
              guest_run_command("tasklist")                              find the PID
              umd_dbgsrv(action="command", pid=<PID>, command="lm")
              umd_dbgsrv(action="command", pid=<PID>, command="~*k")

            ATTACH MODE
              Noninvasive (cdb -pv): memory, modules, threads, PEB and stacks are readable. Breakpoints and
              stepping are not available. The target's threads are suspended while each command runs, so keep
              commands short on a process that must not stall.
              Each command is a fresh cdb.exe run, so debugger state such as .sympath does not carry over.
              Commands that contain a double quote are refused (they travel inside a quoted argument).
              Commands that act on the host are refused by default.

            USEFUL COMMANDS
              ~*k          stacks of all threads        !peb / !teb     process / thread environment block
              lm           loaded modules               !lmi <mod>      module details
              x <mod>!*    exports by pattern           ln <addr>       nearest symbol
              db/dd/dq/du <addr>   memory               !address <addr> region info; !address -summary
              dt ntdll!_PEB @$peb                       !handle 0 f     handle details
              s -b <start> L<len> 4D 5A                 search bytes

            TROUBLESHOOTING
              Cannot reach dbgsrv: dbgsrv not running (start_server), DLLs missing next to it, the guest firewall,
                or a wrong Guest.DbgsrvPassword (error 0x80004005).
              Attach failed: check the PID with guest_run_command("tasklist"). Protected processes refuse the attach.
              cdb.exe timed out: try a smaller command ("lm" before "~*k").
              Two dbgsrv instances on one port conflict.
            """;
    }
}

/// <summary>Time Travel Debugging recordings in the guest. Registered when Tools.Ttd is true.</summary>
[McpServerToolType]
public static class TtdTools
{
    [McpServerTool(Name = "umd_ttd", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false), Description(
        "Time Travel Debugging with TTD.exe in the guest (Guest.TtdPath). 'record_launch' (target = guest exe path, " +
        "arguments) and 'record_attach' (target = PID) start a recording and return at once; 'stop' ends recordings; " +
        "'list' lists trace files; 'retrieve' copies one (target = guest trace path) to outputPath, a host path inside " +
        "Policy.HostTransferRoots. Open traces in WinDbg.")]
    public static async Task<CallToolResponse> UmdTtd(
        StateCoordinator state,
        TtdManager ttd,
        ToolOutput output,
        [Description("What to do")] TtdAction action,
        [Description("record_launch: guest executable path. record_attach: PID. retrieve: guest trace file path.")] string? target = null,
        [Description("record_launch: command-line arguments for the target")] string? arguments = null,
        [Description("retrieve: host file path")] string? outputPath = null,
        CancellationToken ct = default)
    {
        var precheck = await state.ValidatePreconditionsAsync("umd_ttd");
        if (precheck != null) return output.Error("umd_ttd", precheck.Message);

        try
        {
            var text = action switch
            {
                TtdAction.RecordLaunch => string.IsNullOrWhiteSpace(target)
                    ? throw new ArgumentException("Give 'target' with the executable path in the guest.")
                    : await ttd.RecordLaunchAsync(target, arguments ?? "", ct),
                TtdAction.RecordAttach => target == null || !uint.TryParse(target, out var pid)
                    ? throw new ArgumentException("Give 'target' with the PID to record.")
                    : await ttd.RecordAttachAsync(pid, ct),
                TtdAction.Stop => await ttd.StopRecordingAsync(ct),
                TtdAction.List => await ttd.ListTracesAsync(ct),
                TtdAction.Retrieve => string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(outputPath)
                    ? throw new ArgumentException("Give 'target' (guest trace path) and 'outputPath' (host path).")
                    : await ttd.RetrieveTraceAsync(target, outputPath, ct),
                _ => throw new ArgumentException($"Unknown action '{action}'."),
            };
            return output.Ok("umd_ttd", text);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (HostPathRefusedException ex)
        {
            return output.Error("umd_ttd", "REFUSED: " + ex.Message);
        }
        catch (Exception ex)
        {
            return output.Error("umd_ttd", $"umd_ttd {action} failed: {ex.Message}");
        }
    }
}
