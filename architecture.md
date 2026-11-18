# Architecture

This document describes the code as it is in this repository. The upstream project's planning document (VMware era) is in the upstream repository, [memoryforensics1/windbg-mcp](https://github.com/memoryforensics1/windbg-mcp).

## Components

```
src/WinDbgMCP.Server/
  Program.cs                     configuration, validation, tool registration, stdio transport
  ServiceRegistration.cs         the singleton services the tools receive
  ServerInstructions.cs          the MCP "instructions" text (execution model and policies in effect)
  Configuration/
    ServerConfig.cs              typed configuration
    ConfigValidator.cs           startup checks; policy parsing
  Security/
    HostPathPolicy.cs            which host paths the file transfers may use
    HostCommandGuard.cs          refuses debugger commands that act on the host
    Redact.cs                    removes keys, passwords and tokens from log lines
  Processes/
    ToolPaths.cs                 fully qualified paths of ssh, scp, cdb, dbgeng and frida
    ProcessRunner.cs             the one runner for short-lived host programs
  State/
    StateCoordinator.cs          system state and the precondition gate
    SystemState.cs               state model and enums
    ErrorMessages.cs             error texts for the model
    ToolResult.cs, VmResults.cs  result types
  HyperV/
    LabHost.cs                   lifecycle (through LabTaskClient), SSH and SCP, the reachability probe
    LabTaskClient.cs             runs \HyperVLpeLab\<Lab>\<Action> and reads its result file
  KernelDebug/
    DbgEngThread.cs              the one thread that owns DbgEng
    DbgEngManager.cs             connect, execute, break, continue, step, wait, .process /i, event pump
    DebugEventCallbacks.cs       DbgEng event callbacks and the event queue
    OutputCapture.cs             DbgEng output callbacks
    Interop/                     dbgeng.dll loading, the kd_execute command check
  Guest/
    GuestExecManager.cs          guest commands, detached starts, transfers (applies HostPathPolicy)
  UserModeDebug/
    FridaManager.cs              frida.exe / frida-ps.exe and the background session
    DbgsrvManager.cs             cdb.exe -premote against dbgsrv
    TtdManager.cs                TTD.exe in the guest
  Tools/
    MetaTools.cs, VmTools.cs, KernelDebugTools.cs, GuestTools.cs, UserModeDebugTools.cs
    ToolCatalog.cs               which tools a configuration registers, and how each is built
    ToolOutput.cs                every tool result: isError, the output cap, the saved full text
    ToolEnums.cs                 enum parameters and the JSON options the tools use
src/WinDbgMCP.Tests/             offline unit tests
```

Every service is a singleton: one server process controls one VM.

## Startup

1. Set `NoDefaultCurrentDirectoryInExePath=1` for the process, so no executable search by it or its children uses the current directory.
2. Read the configuration file (`WINDBG_HYPERV_MCP_CONFIG`, else `appsettings.json` next to the executable) and the `WINDBG_HYPERV_MCP_*` environment overrides. Nothing is read from the current directory.
3. `ConfigValidator.Validate` checks every value that later reaches a child process, a guest command, a task path or a DbgEng connection string. On any error the server prints all of them to stderr and exits with code 2.
4. `ToolCatalog.Select` picks the tool classes from `Policy.KernelDebug` and `Tools.*`. Each tool of those classes is registered as one `McpServerTool` built by `ToolCatalog.CreateTool`: the SDK's `McpServerTool.Create` with `ToolJson.Options`, after which the name and description copies that the SDK writes into the input schema are removed (the tool already carries both). A tool that is turned off is not registered.
5. The MCP server starts on stdio. All logging goes to stderr; stdout carries only JSON-RPC.

DbgEng is not loaded at startup. `dbgeng.dll` is loaded by full path on the first `kd_connect`.

## Host programs

`ToolPaths` resolves every program to a fully qualified path, and `ProcessRunner` starts it with every argument in `ProcessStartInfo.ArgumentList`, standard input closed, the working directory set to System32, output kept up to 4,000,000 characters per stream, and the whole process tree ended on timeout or cancellation:

| Program | Path |
|---|---|
| `ssh.exe`, `scp.exe` | `Host.OpenSshPath`, else `%SystemRoot%\System32\OpenSSH` |
| `dbgeng.dll`, `cdb.exe` | `Host.DebuggersPath`, else `Debuggers\x64` under `KitsRoot10` (HKLM `SOFTWARE\Microsoft\Windows Kits\Installed Roots`), else under `%ProgramFiles(x86)%\Windows Kits\10` |
| `frida.exe`, `frida-ps.exe` | `Host.FridaToolsPath`, else the first fully qualified, local `PATH` entry that has it |

The fixed working directory matters for cdb.exe in particular: without `-cf`, cdb runs `ntsd.ini` from its current directory as a script.

## Tool results

`ToolOutput` builds every result. Refusals, failed preconditions and failures set `isError`. Text longer than `Limits.MaxOutputChars` (default 48,000 UTF-16 code units) is cut at the last line break before the limit, the full text is written to `<first transfer root>\output\<tool>-<UTC time>-<id>.txt`, and the result ends with a marker that gives both sizes and that file. Two buffers are bounded as well: the run log of `kd_wait_for_event` keeps the last 1,000,000 characters, and the Frida background buffer keeps the last 1,000,000 characters between two `collect_bg` calls.

## The precondition gate

Every tool calls `StateCoordinator.ValidatePreconditionsAsync(name)` first (except `get_system_state`, which only refreshes the state, and `umd_frida` help, collect_bg and stop_bg and `umd_dbgsrv` help, which work in any state). It refreshes the state and returns `null` (go ahead), an error, or a success with a warning (for example "the kernel debugger session will be lost"). An unknown name is an error.

The refresh:

1. reads the execution status that the DbgEng event callbacks cached (no COM call), mapped from dbgeng's `DEBUG_STATUS` by name, and detects a lost session (no debuggee, or no client);
2. reads whether a Frida background session runs;
3. runs one TCP probe of the guest SSH port (22), at most every 2 s. It sets the SSH state, and the power state: a Running VM becomes Off only after two unreachable probes in a row. Paused and Saved are not re-probed, because the probe cannot see them; they change only through `vm_resume`, `vm_stop` or a host Status result. A Running VM whose kernel the debugger holds halted is not probed (it cannot answer);
4. derives "guest tools available" = power Running, SSH reachable, and not halted by the kernel debugger.

`ApplyHostState` takes the Hyper-V state that a lab task reported (`Running`, `Off`, `Paused`, `Saved`) and overrides the probe; the state then records that the host reported it. Every mutator takes the same lock as the refresh, so a refresh that yields during its probe cannot overwrite a mutation (a test reproduces that race).

| Tool | Precondition |
|---|---|
| `get_system_state` | none |
| `vm_start` | power Off or Saved |
| `vm_stop` | none (a hung guest is unreachable; the host task knows the real state); warns if KD is connected |
| `vm_pause` | power Running; warns if KD is connected |
| `vm_resume` | power Paused |
| `kd_connect` | KD not connected, and the VM not known Paused or Saved, and not reported Off by the host. An Off that only the SSH probe inferred is allowed: a guest that is booting, hung in user mode or without sshd still answers KDNET. |
| `kd_disconnect`, `kd_wait_for_event` | KD connected |
| `kd_break` | KD connected, target running |
| `kd_continue` | KD connected, target halted, no bugcheck |
| `kd_step`, `kd_execute` | KD connected, target halted |
| `guest_*`, `umd_frida`, `umd_dbgsrv`, `umd_ttd` | not halted by the kernel debugger, power Running, SSH reachable |

## VM lifecycle

`LabTaskClient` uses the Task Scheduler COM API (`Schedule.Service`), as hyperv-lpe-lab's own `Invoke-HvLabVm.ps1` does:

1. open `\HyperVLpeLab\<Lab>\<Action>` (not found and access denied get their own messages);
2. refuse if the task is already running;
3. note the time and call `Run` with no parameters;
4. poll every 500 ms: first the task state, then `<InstallRoot>\<Lab>\state\<Action>.json`. A result counts only if its `startedUtc` is at or after the trigger time (2 s of slack) and it has a `finishedUtc`, so an older run is never reported;
5. at the tool's timeout, report "pending" if no result has arrived. A task that ended without writing a result is reported with its `LastTaskResult` and the worker log path.

Actions: Start, Stop (guest shutdown), TurnOff (power off), Pause, Resume, Status. The result's `stateAfter` updates the precondition gate. After a successful stop, `ResetAfterStopAsync` ends the kernel debug session on the DbgEng thread, stops a Frida background session and resets the state to a powered-off VM. A lifecycle call waits at most 2 s for another one from this server to finish.

## Guest operations

`ssh.exe user@ip "<cmd>"` runs `chcp 65001>nul & <cmd>` in the guest's OpenSSH default shell, which must be cmd.exe (the Windows OpenSSH default). A PowerShell default shell fails on the `&`; the result then says how to fix the setting. ssh exits 255 both for its own failures and when the remote program exits 255, so 255 is treated as a transport failure only with empty stdout and an ssh diagnostic on stderr.

SSH options: `-i <key>` with `%` doubled (ssh expands `%` tokens there), `BatchMode=yes`, `IdentitiesOnly=yes`, `PasswordAuthentication=no`, the configured `StrictHostKeyChecking`, `UserKnownHostsFile="<file>"` quoted (ssh reads the value as a list separated by spaces; `ConfigValidator` refuses the characters ssh would read differently inside the quotes), and `ConnectTimeout=10`.

`scp.exe` copies files. The host side of every transfer goes through `HostPathPolicy` first; the normalized full path is what reaches scp.

Programs that must outlive the SSH call (frida-server, dbgsrv, TTD.exe) are started with `GuestExecManager.BuildDetachedStart`: a base64-encoded PowerShell script that calls `Invoke-CimMethod Win32_Process Create`. A program started directly from the session (for example with `start /b`) keeps the session's output pipes open, so ssh does not return until it exits, and Windows OpenSSH ends the session's processes when the session closes.

## Kernel debugging

### Thread model

DbgEng objects must be used on the thread that created them. `DbgEngThread` owns one MTA thread and a work queue (it blocks on the queue when idle). `ExecuteAsync` queues a delegate with a timeout. A work item that has not started when its timeout passes never runs. A work item that is running when its timeout passes is interrupted with `SetInterrupt(DEBUG_INTERRUPT_ACTIVE)`, which on a halted target aborts the running command. If it finishes within 5 s, its caller gets its (partial) result with a note. Otherwise its caller gets a timeout, and the thread stays busy with the work item. `SetInterrupt` and `GetInterrupt`, which DbgEng allows from any thread, are the only calls made from other threads.

### Event pump

While the target runs and no work is queued, the DbgEng thread calls `WaitForEvent` with an INFINITE timeout (live kernel targets require it) and nothing interrupts the target. When a tool call queues work, `SetInterrupt(DEBUG_INTERRUPT_EXIT)` ends the wait without breaking into the target; the work runs, then the pump waits again. A watchdog repeats the EXIT while work is queued and, if the wait has not ended 2 s after the first EXIT, falls back to one break-in (`DEBUG_INTERRUPT_ACTIVE`). When the wait returns at a break:

- a breakpoint, second-chance exception or system error stops the pump and leaves the target halted;
- a break that is proven to be a plain debugger break-in (no bugcheck, the target at `DbgBreakPointWithStatus` with `DBG_STATUS_CONTROL_C` in rcx) is resumed: the fallback break-in always, any other at most 5 times per resume;
- any other break (a hard-coded `int 3`, an assertion, a bugcheck) stops the pump; `kd_wait_for_event` reports it as an event.

First-chance exceptions return `DEBUG_STATUS_NO_CHANGE`, so the engine's event filters (`sx` settings) decide whether to break; the default filters break on break instructions and assertions. They are queued for the event summary. Output printed while the target runs (for example by breakpoint commands that end in `gc`) is kept and returned by the next `kd_wait_for_event`.

### Waiting for events

`kd_wait_for_event` has one end-to-end deadline. If the target is already halted and not pumped, it reports the event that halted it without resuming. Otherwise it waits with a timer that sends `DEBUG_INTERRUPT_EXIT` at the deadline, so a wait without an event ends without a break-in and leaves the target running. A break-in is the fallback 2 s later, and the target is resumed after it. A bare break with no event is run past only when it is proven to be a plain debugger break-in (at most 5 per call). Anything else stays halted and is reported.

### Commands that resume the target

`kd_execute` refuses execution-control commands by name (`g`, `gc`, `gh`, `gn`, `gu`, `t`, `p`, `ta`, `pa`, `tc`, `pc`, `tt`, `pt`, `th`, `ph`, `tb`, `tct`, `pct`, `wt`) and session commands (`q`, `qq`, `qd`, `.detach`, `.restart`, `.reboot`). Compound commands are split on `;` outside double quotes, so a quoted breakpoint command such as `bp addr "r rcx; gc"` is allowed; the command name is the run of letters at the start, so `g@$ra` reads as `g`. Two backstops cover what the text check cannot see, such as a `g` inside `.if`: `DEBUG_ENGOPT_DISABLE_EXECUTION_COMMANDS` is set while the command runs, and the execution status is read afterwards. A command that still resumed the target turns the event pump on and says so. `HostCommandGuard` then refuses commands that act on the host (see the README).

### `.process /i`

An invasive context switch only completes after the target runs and breaks back in. `kd_execute` detects the request and marks it pending. The next `kd_continue` turns the pump off, resumes once, and waits up to 30 s for the switch break. Breaks outside the requested EPROCESS that are proven plain break-ins are skipped (at most 5); the target is left halted in the new context, with a warning when the switch may not have completed.

### One session per logon session

`kd_connect` takes the named mutex `Local\WinDbgMCP.KernelDebugOwner` on the DbgEng thread without waiting. A second server instance in the same logon session gets a refusal. The mutex is released on `kd_disconnect`, after `vm_stop`, at shutdown, and, if the process exits, becomes abandoned and can be taken again.

### Engine options and symbols

On connect the server adds `DEBUG_ENGOPT_INITIAL_BREAK`, and `DEBUG_ENGOPT_DISALLOW_SHELL_COMMANDS` when `Policy.BlockHostSideEffectCommands` is on (Microsoft documents that it cannot be unset for the rest of the process). After the initial break it runs `.symopt+0x4; .symopt+0x80; .symopt+0x100; .symopt+0x200; .symopt+0x20000` and a deferred `.reload`. Secure Mode is not used: Microsoft documents that it refuses HTTP and HTTPS symbol servers, which the default symbol path needs.

## User-mode debugging

- Frida: each `eval` and `inject` runs `frida.exe -H <guest>:<port> -p <pid> | -n <name> ...`; hooks live as long as that process unless `--eternalize` is used. `inject_bg` keeps one `frida.exe -t inf` running and buffers its output; a second `inject_bg` is refused while one runs or is still starting. `Guest.FridaToken` reaches frida.exe and frida-ps.exe in the `FRIDA_TOKEN` environment variable.
- dbgsrv: each command runs `cdb.exe -premote tcp:port=<p>,server=<guest>[,password=<pw>] -noshell -y <symbols> -pv -p <pid> -c ".echo <<<START>>>; <cmd>; .echo <<<END>>>; q"` and returns the text between the marker lines. `-pv` suspends the target's threads while cdb.exe is attached. A separate process is used because, as upstream's `DbgsrvManager.cs` states in its header comment, a second in-process DbgEng client does not complete its attach while the kernel session is open.
- TTD: `TTD.exe -accepteula -out <dir> -launch <exe> <args>` or `-attach <pid>`, started in the guest outside the SSH session; `-stop all` ends recordings.

## Timeouts

Every tool returns within a bounded time; the README lists each default and maximum. Guest commands, transfers, Frida and cdb runs end the child process tree when they expire. `vm_*` tools report "pending" at their timeout. `kd_wait_for_event` is capped at 50 s and `kd_execute` at 300 s.

## Error messages

Errors are written for the model: what happened, why, and the next call to make (for example "Call kd_continue to resume the target, then retry when get_system_state shows Guest SSH reachable").
