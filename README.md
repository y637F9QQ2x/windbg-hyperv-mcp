# windbg-hyperv-mcp

[![ci](https://github.com/y637F9QQ2x/windbg-hyperv-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/y637F9QQ2x/windbg-hyperv-mcp/actions/workflows/ci.yml)

An MCP (Model Context Protocol) server for Windows kernel and user-mode debugging of one Hyper-V guest. It is written in C# for .NET 10 and runs on the Windows host as the normal, non-elevated user.

It gives an MCP client (Claude Code, Claude Desktop or any other MCP client) these tools:

- kernel debugging over KDNET or a serial pipe, through DbgEng (the Windows debugger engine) loaded in the server process
- commands and file transfers in the guest, over key-based SSH and SCP
- VM start, stop, power-off, pause and resume, through fixed host tasks that an administrator registers once
- optional tool groups: function hooks in guest processes through Frida, noninvasive inspection of guest processes through dbgsrv and cdb.exe, and Time Travel Debugging (TTD) recordings in the guest

This is a modified version of [memoryforensics1/windbg-mcp](https://github.com/memoryforensics1/windbg-mcp), which drives VMware Workstation through `vmrun`. This version replaces the VMware backend with a Hyper-V backend that needs no elevation, and changes the server in the ways listed in [Changes from upstream](#changes-from-upstream). It is an independent repository, not a GitHub fork, and it is not affiliated with or endorsed by memoryforensics1 or Microsoft.

The host setup (the lifecycle tasks, the guest SSH key setup, the KDNET firewall rule) lives in the companion repository [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab).

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Tools](#tools)
- [Security and trust model](#security-and-trust-model)
- [Limitations](#limitations)
- [Tests](#tests)
- [Changes from upstream](#changes-from-upstream)
- [Related projects](#related-projects)
- [Credits and license](#credits-and-license)

## How it works

```
 MCP client (stdio, JSON-RPC)
      |
 windbg-hyperv-mcp  (host, non-elevated user)
      |-- DbgEng in-process ........ KDNET (UDP) or serial pipe ......> guest kernel
      |-- ssh.exe / scp.exe ........ TCP 22, key-based ...............> guest sshd
      |-- frida.exe / frida-ps.exe . TCP 27042 (Tools.Frida) .........> guest frida-server
      |-- cdb.exe -premote ......... TCP 5064 (Tools.Dbgsrv) .........> guest dbgsrv
      '-- Task Scheduler API ....... runs \HyperVLpeLab\<Lab>\<Action>  (tasks run as SYSTEM,
                                     registered once by an administrator with hyperv-lpe-lab)
```

- The MCP transport is stdio only. The server opens no listening socket of its own, and `kd_execute` refuses `.server`, the debugger command that would open one, unless `Policy.BlockHostSideEffectCommands` is turned off.
- A `StateCoordinator` checks the preconditions of every tool call (for example: guest tools need the guest reachable and not frozen at a kernel break) and returns an error that says what to do next.
- Every DbgEng call runs on one dedicated thread, because DbgEng objects have thread affinity. While the target runs, that thread waits for debug events and does not interrupt the target. A tool call ends that wait with `DEBUG_INTERRUPT_EXIT`, which returns without breaking into the target.
- Details: [architecture.md](architecture.md).

**Why an MCP server and not a command-line tool.** A kernel debugging session is state that must last across calls: the DbgEng session, its event wait, and the ownership mutex that keeps a second instance off the same guest. A tool that runs once per command would reconnect KDNET and break into the guest for every command.

## Requirements

Host:

- Windows 10 or 11, or Windows Server, with Hyper-V.
- The [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) to build, and the .NET 10 runtime to run. The server targets `net10.0-windows` (win-x64); `global.json` asks for SDK 10.0.100 or a later 10.0 SDK.
- Debugging Tools for Windows (the "Debugging Tools for Windows" feature of the Windows SDK) for `dbgeng.dll` and `cdb.exe`. The server finds them under the Windows Kits root that the SDK installer records in the registry; set `Host.DebuggersPath` for another folder.
- The Windows OpenSSH client (`%SystemRoot%\System32\OpenSSH\ssh.exe` and `scp.exe`, an optional Windows feature); set `Host.OpenSshPath` for another folder.
- The host tasks from [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab), installed once by an administrator for the account that runs this server. Without them the `vm_*` tools return "task not found"; the other tools still work.
- Optional, for `Tools.Frida`: [frida-tools](https://frida.re/) (`pip install frida-tools`), the same Frida version as the guest's frida-server.

Guest:

- Windows x64 with OpenSSH Server and key-based login for the account in `Vm.GuestUsername`. hyperv-lpe-lab's `guest\Install-HvLabGuestSsh.ps1` sets this up.
- cmd.exe as the OpenSSH default shell, which is the Windows default: the server sends cmd.exe syntax. A `DefaultShell` value under `HKLM\SOFTWARE\OpenSSH` that names PowerShell makes every guest tool fail (the error then says so).
- A static IPv4 address on a Hyper-V Internal switch shared with the host (see [Network](#network)).
- For kernel debugging: KDNET enabled in the guest and an inbound UDP rule on the host. Follow hyperv-lpe-lab's [KDNET guide](https://github.com/y637F9QQ2x/hyperv-lpe-lab/blob/main/docs/kdnet-and-dumps.md): `bcdedit /dbgsettings net hostip:<host-ip> port:50000` generates a random key and prints it (put it in `KernelDebug.Kdnet.Key`), then `bcdedit /debug on` and a restart. With Secure Boot on in the VM settings, `bcdedit` can refuse the debug settings.
- Optional: `frida-server.exe`, `dbgsrv.exe` (with `dbgeng.dll` and `dbghelp.dll` from the same Debugging Tools build in the same folder), `TTD.exe`.

## Install

```powershell
git clone https://github.com/y637F9QQ2x/windbg-hyperv-mcp.git
cd windbg-hyperv-mcp
dotnet build -c Release
dotnet test -c Release
```

The server executable is `src\WinDbgMCP.Server\bin\Release\net10.0-windows\win-x64\WinDbgMCP.Server.exe`.

Create the configuration from the example, outside the repository:

```powershell
Copy-Item src\WinDbgMCP.Server\appsettings.example.json $env:USERPROFILE\windbg-hyperv-mcp.json
notepad $env:USERPROFILE\windbg-hyperv-mcp.json
```

The file holds the guest account and the KDNET key. The build copies no configuration file into its output, and `.gitignore` excludes `appsettings*.json` (except the example), `windbg-hyperv-mcp*.json` and `*.bak*`. Build a binary that you give to anyone else from a clean clone.

The server reads the file named by the environment variable `WINDBG_HYPERV_MCP_CONFIG`, or `appsettings.json` next to the executable. It checks the configuration at startup ([Checked at startup](#checked-at-startup)), prints every problem to stderr and exits with code 2 if one is found.

Register the server with your MCP client. Start the executable directly. Do not use `dotnet run`: it can print build output on stdout, which is the MCP channel.

Claude Code:

```powershell
claude mcp add windbg-hyperv -e WINDBG_HYPERV_MCP_CONFIG=C:\Users\<you>\windbg-hyperv-mcp.json -- C:\path\to\windbg-hyperv-mcp\src\WinDbgMCP.Server\bin\Release\net10.0-windows\win-x64\WinDbgMCP.Server.exe
```

Claude Desktop and other clients that use an `mcpServers` JSON file:

```json
{
  "mcpServers": {
    "windbg-hyperv": {
      "command": "C:\\path\\to\\windbg-hyperv-mcp\\src\\WinDbgMCP.Server\\bin\\Release\\net10.0-windows\\win-x64\\WinDbgMCP.Server.exe",
      "env": { "WINDBG_HYPERV_MCP_CONFIG": "C:\\Users\\<you>\\windbg-hyperv-mcp.json" }
    }
  }
}
```

## Usage

Example workflows, as sequences of tool calls.

Inspect a running kernel (operator present):

```
kd_connect
kd_execute("lm")
kd_execute("!process 0 0")
kd_disconnect
```

Break on a function and look at the stack:

```
kd_connect
kd_execute("bp nt!NtCreateFile")
kd_continue
kd_wait_for_event(30)
kd_execute("k")
kd_disconnect
```

Deploy a test driver (copy it into the transfer folder first). A default guest refuses to load an unsigned driver: it needs test signing (`bcdedit /set testsigning on` and a restart) or an attached kernel debugger, and Memory Integrity (HVCI) off.

```
guest_transfer_to_vm("%LOCALAPPDATA%\\windbg-hyperv-mcp\\transfer\\MyDrv.sys", "C:\\Windows\\System32\\drivers\\MyDrv.sys")
guest_run_command("sc create MyDrv type= kernel binPath= C:\\Windows\\System32\\drivers\\MyDrv.sys")
guest_run_command("sc start MyDrv")
```

Hook a function with Frida (`Tools.Frida`):

```
umd_frida(action="start_server")
umd_frida(action="inject_bg", processName="notepad.exe", code="Interceptor.attach(Process.getModuleByName('kernel32.dll').getExportByName('CreateFileW'), { onEnter(a) { console.log(a[0].readUtf16String()); } });")
umd_frida(action="collect_bg")
umd_frida(action="stop_bg")
```

Inspect a guest process through dbgsrv (`Tools.Dbgsrv`); its threads are suspended while each command runs:

```
umd_dbgsrv(action="start_server")
guest_run_command("tasklist")
umd_dbgsrv(action="command", pid=<pid>, command="!peb")
```

Recover a hung guest:

```
vm_stop(turnOff=true)
vm_start
```

## Configuration

All keys, with their defaults. Environment variables with the prefix `WINDBG_HYPERV_MCP_` override single keys, with `__` between levels (for example `WINDBG_HYPERV_MCP_Vm__GuestIpAddress`). A restart applies changes.

| Key | Default | Meaning |
|---|---|---|
| `Vm.VmName` | (required) | Hyper-V VM name, shown by `get_system_state`. The lab tasks decide which VM they control. |
| `Vm.GuestIpAddress` | (required) | Guest IPv4 address, used for SSH, Frida and dbgsrv. |
| `Vm.GuestUsername` | (required) | Guest account for SSH. Letters, digits, `.`, `_`, `-`. |
| `Vm.Lab` | (required) | Lab name given to hyperv-lpe-lab at install. Tasks are `\HyperVLpeLab\<Lab>\<Action>`. |
| `Vm.InstallRoot` | `%ProgramData%\HyperVLpeLab` | hyperv-lpe-lab install root; results are read from `<InstallRoot>\<Lab>\state\<Action>.json`. |
| `Vm.HostPrivateKeyPath` | `%USERPROFILE%\.ssh\id_ed25519` | SSH private key for the guest. Must exist. |
| `Vm.KnownHostsFile` | `%USERPROFILE%\.ssh\windbg-hyperv-mcp_known_hosts` | known_hosts file used only for the guest. Its folder must exist. Spaces are fine; `"`, `%`, `\\`, `\'` and a trailing `\` are refused, because ssh would read them differently. |
| `Vm.StrictHostKeyChecking` | `accept-new` | `accept-new` (trust the first key seen) or `yes` (the key must already be in the file). |
| `KernelDebug.Transport` | `kdnet` | `kdnet` or `serial`. |
| `KernelDebug.Kdnet.Port` / `.Key` | `50000` / empty | KDNET port, and the key that `bcdedit /dbgsettings` printed in the guest. |
| `KernelDebug.Serial.PipeName` | `\\.\pipe\com_1` | Local named pipe of the VM's COM port, for `serial`. |
| `KernelDebug.SymbolPath` | `srv*%LOCALAPPDATA%\windbg-hyperv-mcp\symbols*https://msdl.microsoft.com/download/symbols` | Symbol path for `kd_*` and for the cdb.exe runs of `umd_dbgsrv`. Environment variables are expanded. |
| `Guest.FridaPort` / `Guest.DbgsrvPort` | `27042` / `5064` | Guest ports. |
| `Guest.FridaServerPath`, `Guest.DbgsrvPath` | `C:\Tools\frida-server.exe`, `C:\Tools\DbgSrv\dbgsrv.exe` | Guest paths that `start_server` starts. |
| `Guest.TtdPath` / `Guest.TtdOutputDirectory` | `C:\Tools\TTD\TTD.exe` / `C:\TTD_Traces` | Guest TTD paths. |
| `Guest.FridaToken` | empty | frida-server token: letters, digits, `.`, `_`, `-`. See [Network](#network). |
| `Guest.DbgsrvPassword` | empty | dbgsrv password: 1 to 12 letters or digits. See [Network](#network). |
| `Host.DebuggersPath` | empty (`Debuggers\x64` of the installed Windows Kit) | Folder with `dbgeng.dll` and `cdb.exe`. |
| `Host.FridaToolsPath` | empty (the `PATH` folders) | Folder with `frida.exe` and `frida-ps.exe`. An MCP client can start the server with a shorter `PATH` than your shell; then set this. |
| `Host.OpenSshPath` | empty (`%SystemRoot%\System32\OpenSSH`) | Folder with `ssh.exe` and `scp.exe`. |
| `Tools.Frida` / `Tools.Dbgsrv` / `Tools.Ttd` | `false` / `false` / `false` | Register `umd_frida`, `umd_dbgsrv`, `umd_ttd`. |
| `Policy.KernelDebug` | `Attended` | `Attended`, `Enabled` or `Disabled`. See [Kernel debugging policy](#kernel-debugging-policy). |
| `Policy.BlockHostSideEffectCommands` | `true` | Refuse debugger commands that act on the host. See [Debugger commands](#debugger-commands-that-act-on-the-host). |
| `Policy.HostTransferRoots` | empty (`%LOCALAPPDATA%\windbg-hyperv-mcp\transfer`) | Host folders that file transfers may use; cut tool results are saved in `output` under the first one. `["*"]` turns the folder check off. |
| `Limits.MaxOutputChars` | `48000` | Longest tool result, 8000 to 500000. See [How results are bounded](#how-results-are-bounded). |
| `Timeouts.*` | see `appsettings.example.json` | Seconds, 1 to 3600. See [Time limits](#time-limits). |

### Checked at startup

The server stops with exit code 2 when:

- a required `Vm.*` value is missing, or the guest address is not an IPv4 literal, the account or the lab name has other characters than allowed;
- `Vm.InstallRoot`, `Vm.HostPrivateKeyPath`, `Vm.KnownHostsFile`, a `Host.*` folder or a `Policy.HostTransferRoots` entry is not a fully qualified local path;
- the key file, or the folder of the known_hosts file, does not exist;
- the KDNET key is not four words of letters and digits separated by dots (unless kernel debugging is disabled), or the serial pipe is not a local `\\.\pipe\` name;
- a guest path or the symbol path contains a quote or a line break, or the Frida token or the dbgsrv password has other characters than allowed;
- a port, a timeout or `Limits.MaxOutputChars` is out of range, or `Policy.KernelDebug`, `KernelDebug.Transport` or `Vm.StrictHostKeyChecking` has an unknown value.

A JSON null counts as empty. The messages never contain the KDNET key, the token or the password.

## Tools

| Tool | What it does |
|---|---|
| `get_system_state` | VM, kernel debugger and guest-tool state. `queryHost=true` also runs the host Status task for the Hyper-V state. |
| `vm_start`, `vm_stop`, `vm_pause`, `vm_resume` | Run the host Start, Stop (guest shutdown), TurnOff (`vm_stop(turnOff=true)`), Pause and Resume tasks. |
| `kd_connect`, `kd_disconnect` | Attach DbgEng to the guest kernel over the configured transport, and detach (a halted target is resumed first). |
| `kd_break`, `kd_continue`, `kd_step` | Halt, resume, single-step (`over` or `into`). |
| `kd_execute` | Run a WinDbg command while the target is halted. Commands that resume the target are refused; use `kd_continue` and `kd_step`. |
| `kd_wait_for_event` | Wait up to 50 s for a breakpoint, exception or assertion, without interrupting the target. |
| `guest_run_command` | Run a cmd.exe command in the guest over SSH (`tasklist`, `taskkill /F /PID <pid>` and so on). |
| `guest_transfer_to_vm`, `guest_transfer_from_vm` | Copy a file to or from the guest with SCP. Host paths must be inside `Policy.HostTransferRoots`. |
| `umd_frida` (`Tools.Frida`) | Frida `eval` and `inject` (one-shot or eternalized) by `pid` or `processName`, background scripts (`inject_bg`, `collect_bg`, `stop_bg`), `list`, `start_server`, `help`. |
| `umd_dbgsrv` (`Tools.Dbgsrv`) | A WinDbg command against a guest process through dbgsrv and a fresh, noninvasive cdb.exe (`command`), `start_server`, `help`. |
| `umd_ttd` (`Tools.Ttd`) | Start a TTD recording in the guest, stop recordings, list traces, copy a trace to the host. |

Every tool sets all four MCP annotation hints, with `openWorldHint` false, and a refusal or failure comes back with `isError` set. Parameters with a fixed set of values are enums, so the input schema lists the values.

### Tool count and context cost

**Measured definition size.** Characters of the tool definitions the server sends (name, description, input schema and annotations, as compact JSON), measured by `ToolListSizeTests`. The test builds every tool through `ToolCatalog.CreateTool`, the code the server registers tools with, and fails when the numbers below no longer match the code. Measured on 2026-11-18 with .NET SDK 10.0.302 (runtime 10.0.10) and ModelContextProtocol 0.1.0-preview.12. The SDK sends each apostrophe, `<`, `>` and `+` as a six-character escape sequence (`\u0027` and so on); the table counts each as one character, as a client sees it after parsing. The token column is characters divided by 4, a rough estimate: the real count depends on the model's tokenizer and on how the client presents tool definitions.

| Configuration | Tools | Characters | About tokens |
|---|---|---|---|
| defaults (kernel debugging on, no Frida, dbgsrv or TTD) | 15 | 7,096 | 1,774 |
| `Policy.KernelDebug` = `Disabled` | 8 | 4,044 | 1,011 |
| every tool group on | 18 | 10,456 | 2,614 |

The server also sends instructions once per session: 2,115 characters for the test configuration. Their length depends on the VM name, the guest address and account, and the transfer folders.

Four choices keep the definitions small. Tool groups that are off are not registered. The input schemas do not repeat the tool name and description: the SDK copies both into the schema, and the server removes the copies. The Frida and dbgsrv reference texts are returned by `action="help"` only when asked. And related actions share one tool (`umd_frida` has an `action` enum instead of one tool per action).

### How results are bounded

Claude Code saves a text result longer than 50,000 characters to a file instead of showing it, and its `MAX_MCP_OUTPUT_TOKENS` setting (default 25,000 tokens) limits a result too (Claude Code documentation, "Environment variables"). This server keeps every result at or below `Limits.MaxOutputChars` (default 48,000; 8,000 to 500,000), counted in UTF-16 code units, as JavaScript counts string length:

- A longer result is cut at the last line break before the limit and ends with `[windbg-hyperv-mcp: the result was cut after N of M characters ...]`. The full text is saved to `output\<tool>-<UTC time>-<id>.txt` under the first transfer folder, and the marker names that file. Saved results stay until you delete them.
- The output of a host program is read up to 4,000,000 characters per stream, and DbgEng output up to 4,000,000 characters between two reads. The output that breakpoint commands print while the target runs is kept up to the last 1,000,000 characters, and so is the output of a Frida background script between two `collect_bg` calls. Each one says how much it dropped.

### Time limits

Every call returns within a bounded time. The MCP TypeScript SDK gives up on a request after 60 s by default (`DEFAULT_REQUEST_TIMEOUT_MSEC`), so clients built on it need their own setting for a longer call. Claude Code has its own time limits for a tool call (for example `MCP_TOOL_TIMEOUT`); check its documentation for the current ones. The defaults below keep every call under 60 s; a larger `timeoutSeconds` needs a client that waits that long.

| Tool | Default | Maximum | Setting |
|---|---|---|---|
| `get_system_state` | 3 s probe; with `queryHost`, 30 s for the Status task | | `Timeouts.VmStateQuerySeconds`, `Timeouts.VmStatusSeconds` |
| `vm_start` | 45 s, then "pending" | | `Timeouts.VmStartSeconds` |
| `vm_stop` | 30 s, then "pending"; with a kernel debug session, up to 16 s before and 10 s after the stop to close it | | `Timeouts.VmStopSeconds` |
| `vm_pause`, `vm_resume` | 10 s, then "pending" | | `Timeouts.VmPauseResumeSeconds` |
| `kd_connect` | 30 s | | `Timeouts.KdConnectSeconds` (initial break: `KdInitialBreakSeconds`, 15 s) |
| `kd_disconnect` | 16 s | | |
| `kd_break`, `kd_step` | 10 s, plus 2 s | | `Timeouts.KdBreakSeconds`, `Timeouts.KdStepSeconds` |
| `kd_continue` | 5 s; 30 s with a pending `.process /i` | | |
| `kd_execute` | 30 s | 300 s | `timeoutSeconds`; an interrupted command gets 5 s more to stop |
| `kd_wait_for_event` | 10 s | 50 s | `timeoutSeconds`; plus 2 s if the wait needs the fallback break-in |
| `guest_run_command` | 45 s | 3600 s | `timeoutSeconds`, default `Timeouts.GuestCommandSeconds` |
| `guest_transfer_*`, `umd_ttd` retrieve | 45 s | | `Timeouts.GuestFileTransferSeconds` |
| `umd_frida` eval, inject | 30 s | 3600 s | `timeoutSeconds` (inject: plus 5 s) |
| `umd_frida` list, start_server | 15 s, 30 s | | |
| `umd_dbgsrv` command, start_server | 30 s, 30 s | 600 s | `timeoutSeconds` |
| `umd_ttd` record, stop, list | 40 s, 30 s, 10 s | | |

Long work uses a start and a poll call: `kd_continue` then `kd_wait_for_event`, `umd_frida` `inject_bg` then `collect_bg`, and `umd_ttd` record (it returns at once) then `list`.

## Security and trust model

This is a tool for a lab you own. It gives the MCP client, and therefore the model, administrator control over one guest. This section states what it trusts, what it protects, and what it does not. To report a security problem, see [SECURITY.md](SECURITY.md).

### Accounts and privileges

- The server runs as the interactive user, not elevated. It never asks for elevation and has no code path that elevates.
- The `vm_*` tools run tasks that an administrator registered once with hyperv-lpe-lab. Those tasks run as SYSTEM, take no parameters, and run a fixed worker script from a folder that only SYSTEM and Administrators can change. Their security descriptor lets only the operator account named at install run them. The server starts a task (Task Scheduler API, `IRegisteredTask.Run` with no arguments) and reads the result file. It creates, changes and deletes no task.
- So the operator account, and any program that runs as that account, can start, stop, turn off, pause and resume that one VM and read its status, and nothing more through these tasks. That is the intended delegation, and it is narrower than membership in the Hyper-V Administrators group (see below). It stays that narrow as long as the worker folder stays writable only by SYSTEM and Administrators, which hyperv-lpe-lab's installer sets and its `Test-HvLabInstall.ps1` checks.
- The guest tools run as `Vm.GuestUsername` in the guest, normally a guest administrator. Results from that account do not show what a standard user can do; use a separate standard-user account for that (hyperv-lpe-lab's guest script sets up SSH for one existing standard account).

**A standard user starts a task that runs as SYSTEM. Is that a UAC bypass?** No. An administrator registers the tasks once, from an elevated installer. Each task runs one of six fixed actions (Start, Stop, TurnOff, Pause, Resume, Status) on one VM and takes no input: the server calls `Run` with no parameters, and the worker reads nothing the operator can write. What the operator account gains is those six actions on that VM, which is what the administrator granted.

**Why not add the account to Hyper-V Administrators?** That group controls every VM on the host and the host's Hyper-V settings, including which disks are attached to a VM. That is far broader than six fixed actions on one VM.

### Network

- The MCP connection is stdio only. The server opens no listening socket, so there is no HTTP endpoint that a browser page could reach (no DNS rebinding or cross-site request path). `kd_execute` refuses `.server` (unless `Policy.BlockHostSideEffectCommands` is turned off), and cdb.exe runs only with `-premote` to the configured guest.
- During a kernel debug session DbgEng listens on the KDNET UDP port on every host adapter. KDNET encrypts its traffic with the key; keep the key out of shared files. hyperv-lpe-lab's firewall rule for that port admits only the addresses given to `Install-HvLab.ps1 -KdnetRemoteAddress` (required with `-KdnetPort`; use the internal switch's address prefix), and with `-KdnetInterfaceAlias` only on that host adapter. If `kd_connect` times out, check which address the guest's KDNET transport uses: it can differ from the guest's Windows address.
- In the guest, `frida-server` and `dbgsrv` accept connections without authentication unless they are started with a token (frida-server `--token`) or a password (dbgsrv `password=`). Set `Guest.FridaToken` and `Guest.DbgsrvPassword`, and `start_server` uses them; frida.exe and frida-ps.exe get the token in the `FRIDA_TOKEN` environment variable. Microsoft documents that a dbgsrv password on the tcp transport travels unencrypted and offers only a small amount of protection. Anyone who reaches those ports without them can inject code into, or read the memory of, guest processes.
- Put the guest on a Hyper-V **Internal** switch (host and VMs only). A Private switch has no host adapter, so the host cannot reach the guest at all. An External switch puts the guest's ports on the physical network. `start_server` binds frida-server to the guest address. Allow both ports in the guest firewall from the host address only; `action="help"` shows the commands.
- SSH uses the configured key only (`IdentitiesOnly=yes`, `BatchMode=yes`, no password login) and a known_hosts file used only for this guest. With `StrictHostKeyChecking=accept-new` the first host key seen is trusted; set `yes` and pre-populate the file if you need the key pinned before the first connection. A reinstalled guest has a new host key; the error then says how to remove the old line (`ssh-keygen -R <guest-ip> -f <known_hosts>`), after you have checked the new key.

### Input from the model

The model chooses tool arguments, and text from the guest can influence the model. The server limits what those arguments can do on the host:

- Every host program is started by its full path (see [architecture.md](architecture.md#host-programs)), never by a bare name, with the working directory set to System32 and `NoDefaultCurrentDirectoryInExePath=1`. A planted `ssh.exe`, `frida.exe` or `cdb.exe` in the client's working folder is never run, and cdb.exe never reads an `ntsd.ini` from there. PATH entries that are relative or UNC are skipped when the server looks for frida.
- Child processes (`ssh`, `scp`, `frida`, `frida-ps`, `cdb`) get every argument through `ProcessStartInfo.ArgumentList`, so an argument cannot add options. The guest account, guest address and lab name are validated at startup; a value starting with `-` (which `ssh` would parse as an option) is refused.
- The connection target is not a tool argument. `kd_connect` uses the configured transport (the serial pipe must be local), and the Frida and dbgsrv tools connect only to `Vm.GuestIpAddress` and the configured ports.
- File transfers use only host paths inside `Policy.HostTransferRoots` (default `%LOCALAPPDATA%\windbg-hyperv-mcp\transfer`). Environment variables in the path are expanded first. The path must be fully qualified; UNC, device and alternate-data-stream paths are refused, `..` cannot leave the folder, and a junction or symbolic link under the folder is refused. Without this, a file pulled from an untrusted guest could be written to a host autostart folder, or a host secret such as an SSH key could be sent to the guest.
- `umd_dbgsrv` refuses commands that contain a double quote, because the command travels inside a quoted `cdb.exe` argument.

### Debugger commands that act on the host

`kd_execute` runs DbgEng inside this server process, and `umd_dbgsrv` runs `cdb.exe` on the host. Some debugger commands act on the host, not on the target. With `Policy.BlockHostSideEffectCommands` (the default) the server refuses these, anywhere in the command, quoted breakpoint commands included:

- Every dot-command at the start of a command except `.lastevent`, `.process`, `.thread`, `.context`, `.cxr`, `.exr`, `.ecxr`, `.trap`, `.frame`, `.f+`, `.f-`, `.bugcheck`, `.reload`, `.effmach`, `.time`, `.formats`, `.echo`, `.printf`, `.bpcmds` and the control-flow commands `.if`, `.elsif`, `.else`, `.for`, `.while`, `.do`, `.break`, `.continue`, `.block`, `.catch`, `.leave`. Every other documented dot-command is also refused where it is not at the start of a command, for example after `j 1 ` or `~*e `. This covers `.shell`, `.load`, `.writemem`, `.dump`, `.logopen`, `.readmem`, `.kdfiles`, `.scriptload`, `.server`, `.send_file`, `.copysym`, `.dbgdbg`, `.settings`, `.sympath`, `.srcpath`, `.exepath`, `.symfix`, `.foreach`, `.ocommand` and the rest.
- `.reload` with a file path.
- Script files (`$<` and its variants), alias definitions (`as`, `aS`, `r $.u0`), `lsf`, and the `!for_each_*` extensions. These read host files, or run text that the target controls as commands.
- `!dll.command` unless the DLL is `kdexts`, `kext`, `ext`, `exts`, `uext`, `ntsdexts` or `dbghelp`, and extension commands named `*logsave`, `*tmffile` or `*searchpath` (trace logs on the host).
- `dx` access to `Debugger.Utility` other than `Collections` and `Code`, to `Debugger.Settings`, and to the extension gallery.
- A UNC or device path (`\\server\share`, `\\?\`, `\\.\`, `//server/share`) or a URL. A debugger command has no need for one, and a UNC path makes the host send the user's NTLM credentials to that server.

The engine enforces two parts itself. `.shell` is disabled by `DEBUG_ENGOPT_DISALLOW_SHELL_COMMANDS` in the server process and by `-noshell` for cdb.exe. Commands that resume the target are disabled by `DEBUG_ENGOPT_DISABLE_EXECUTION_COMMANDS` while a `kd_execute` command runs.

The rest is a text filter, not a sandbox: an extension command that reads or writes host files under a name this list does not cover would pass. Secure Mode, DbgEng's own lockdown for kernel debugging, is not used, because Microsoft documents that it refuses HTTP and HTTPS symbol servers. The security boundary is the Windows account the server runs as. If the model must not be able to act on the host at all, do not give it a debugger.

### Secrets

- The KDNET key, `Guest.FridaToken` and `Guest.DbgsrvPassword` stay in the configuration file. The server never puts them into the server instructions, a tool result or a log line (log lines show `<redacted>`); tests check the instructions and the help texts. The guest holds the same key, token and password, so an administrator in the guest can read them (the key with `bcdedit /dbgsettings`), and `guest_run_command` can return them. The dbgsrv password is also on the host's cdb.exe command line, which the same user and administrators can read, and which `umd_dbgsrv` returns for a debugger command that prints it (`vercommand`).
- The SSH private key is only passed to `ssh.exe` and `scp.exe` by path.
- Keep the configuration file outside the repository (see [Install](#install)). Only `appsettings.example.json`, with placeholders, is tracked.

### Kernel debugging policy

A kernel break freezes the whole guest, and a debugger can change guest kernel memory. `Policy.KernelDebug` has three values:

- `Attended` (default): the `kd_*` tools are registered, and the server instructions tell the model to use them only while the user watches the session, never in an unattended or autonomous run. This is guidance for the model, not a technical control. The technical control is your MCP client's per-tool approval: keep the `kd_*` tools on "ask".
- `Enabled`: the tools are registered without that guidance.
- `Disabled`: the `kd_*` tools are not registered at all, so the model cannot call them and their descriptions do not use context.

### No checkpoint restore

This server has no checkpoint (snapshot) tools and never reverts the guest. A revert discards everything installed in the guest since the checkpoint. hyperv-lpe-lab has no checkpoint action, and a restore would need a checkpoint name passed into a SYSTEM task, a parameter across the privilege boundary that its fixed-action tasks avoid. Use Hyper-V Manager for checkpoints. To recover a hung guest, use `vm_stop(turnOff=true)` and `vm_start`.

## Limitations

- One server process controls one VM, over IPv4 only.
- x64 guests only: telling a debugger break-in from other breaks reads `@rip` and `@rcx` and looks for `nt!DbgBreakPointWithStatus`.
- VM power is inferred from guest SSH reachability: Off also covers paused, booting and no network. `get_system_state(queryHost=true)` asks Hyper-V through the Status task.
- A `vm_*` tool waits up to its timeout and then reports "pending"; the host task keeps running and writes its result later.
- While the target runs, a tool call that needs the DbgEng thread ends the debugger's wait with `DEBUG_INTERRUPT_EXIT`, which does not break into the target. If the wait has not ended 2 s later, the server breaks in once and resumes the target. How often that fallback happens on a live guest has not been measured.
- There is no invasive user-mode debugger. dbgsrv attaches are noninvasive (no breakpoints, no stepping) and suspend the target's threads while a command runs. Each command is a separate `cdb.exe` run, so debugger state such as `.sympath` does not carry over. Commands that contain a double quote are refused.
- `kd_wait_for_event` waits at most 50 s per call. Call it again to keep waiting.
- Only one kernel debug session per Windows logon session: a second server instance gets a clear refusal from `kd_connect` while the first holds the session.
- On connect the server sets five symbol options: `.symopt+0x4` (SYMOPT_DEFERRED_LOADS), `+0x80` (SYMOPT_IGNORE_CVREC: ignore the path stored in an image's CodeView record), `+0x100` (SYMOPT_NO_UNQUALIFIED_LOADS: a symbol without a module name, such as `x Foo`, searches only modules whose symbols are loaded; write `nt!Foo`), `+0x200` (SYMOPT_FAIL_CRITICAL_ERRORS) and `+0x20000` (SYMOPT_NO_IMAGE_SEARCH). Microsoft documents 0x4, 0x200 and 0x20000 as debugger defaults.
- Turning on `Tools.Ttd` accepts the TTD.exe license terms on your behalf: recordings pass `-accepteula`. A recording runs in the guest outside the SSH session, without a visible desktop. `umd_ttd` records and copies traces; it does not analyze them. Open them in WinDbg.
- The frida-tools version on the host must match the frida-server version in the guest.
- The server uses the prerelease MCP C# SDK `ModelContextProtocol` 0.1.0-preview.12 (packed on 2025-05-05, per the file dates in the package). Its API changed in later releases; this code has not been ported to them.
- The host command filter is a text filter (see above).
- No automated test covers the live paths (Task Scheduler, SSH, SCP, KDNET, Frida, dbgsrv, TTD). See [Tests](#tests).

## Tests

```powershell
dotnet test -c Release
```

The tests are offline unit tests. They start no VM, no SSH or SCP, no debugger and no Frida, open no network connection and do not use the Task Scheduler. They cover:

- the precondition gate, including the one SSH probe per refresh and the `kd_connect` rule;
- the `kd_execute` command check and the host command filter, with the commands each one must refuse and allow;
- the configuration checks, the host path policy, and the redaction of log lines and of cdb's failure output;
- the lab result parser; the argument lists of ssh, scp, frida, frida-ps and cdb; the guest command lines (cmd.exe, the detached start, TTD); the fully qualified program paths; and the one Frida background slot;
- the output cap and the saved full text; the DbgEng work thread (timeouts and interrupts) with plain delegates instead of DbgEng; and the mapping of DbgEng's execution status;
- the tool catalog per policy, the annotations, the input schemas and the definition sizes published above;
- the server instructions and help texts (no secrets, no profile path), and the service registration (every service a tool asks for resolves);
- two checks over the repository's text files: no em or en dash, and no private-range IPv4 address. In a git working tree they read the files that `git ls-files` lists (so the test runs git); elsewhere every file except the local ones that `.gitignore` names.

Some tests create and delete a folder under `%TEMP%`; one of them creates a directory junction inside it (no privilege needed) to check that the path policy refuses it. The CI workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs restore, build and test on `windows-latest`.

**Live checks.** These need a lab VM and have not been run against this version. Check them by hand after setup:

1. `get_system_state(queryHost=true)`, `vm_stop` and `vm_start`, then `vm_stop(turnOff=true)` and `vm_start`.
2. `guest_run_command("whoami")`, and one transfer in each direction inside the transfer folder.
3. With `Tools.Frida`: `umd_frida(action="start_server")`, then `action="list"` (it must still answer after the SSH call has returned), an `eval`, and `inject_bg`, `collect_bg`, `stop_bg`.
4. With `Tools.Dbgsrv`: `umd_dbgsrv(action="start_server")`, then `umd_dbgsrv(action="command", pid=<pid>, command="lm")`.
5. With an operator present: `kd_connect`, `kd_execute("lm")`, `kd_continue`, `kd_wait_for_event(10)` with no event (the target must keep running, with no break-in), `kd_break`, `kd_disconnect`.
6. With an operator present: a test driver that calls `DbgBreakPoint()`, and one that fails an `NT_ASSERT`. After `kd_continue`, load the driver; `kd_wait_for_event` must report the break and leave the target halted.
7. With sshd stopped in the guest: `kd_connect` must still connect.

## Changes from upstream

Upstream: [memoryforensics1/windbg-mcp](https://github.com/memoryforensics1/windbg-mcp), commit `9a5f693505dac7cdc8d20622681ff4d764e5ca43` (2026-02-14), MIT license, "Copyright (c) 2025 memoryforensics1". The C# namespaces (`WinDbgMCP.*`) and project names are kept.

Hypervisor backend:

- Removed the VMware Workstation backend (`Vmware/VmwareManager.cs`, `vmrun`) and the `vm_screenshot` tool.
- Added `HyperV/LabHost.cs` and `HyperV/LabTaskClient.cs`: lifecycle through the hyperv-lpe-lab tasks (Task Scheduler API, result files), guest commands over `ssh.exe`, transfers over `scp.exe`, and the guest state from one TCP probe of the guest SSH port per refresh. The server needs no elevation.
- `vm_stop` now has a meaningful `turnOff` switch (guest shutdown or power-off). `get_system_state` has `queryHost` for the Hyper-V state. A state reported by a host task updates the precondition gate, so a VM paused outside the server can be resumed.
- Removed `vm_snapshot_list`, `vm_snapshot_restore` and `vm_set_target`. The host automation has no checkpoint action, and a restore would need a checkpoint name passed into a SYSTEM task. `vm_set_target` could only change the SSH user, not the VM that the host tasks control.
- Guest-related error texts describe SSH reachability instead of VMware Tools.

Kernel debugging:

- The event pump no longer breaks into the target once a second. It waits without a timer and is ended with `DEBUG_INTERRUPT_EXIT` when a tool call needs the DbgEng thread, with one break-in as the fallback.
- `kd_wait_for_event` has one end-to-end deadline, at most 50 s (upstream: 120 s). At the deadline it ends the wait with `DEBUG_INTERRUPT_EXIT`, so a timeout leaves the target running untouched. It runs past a stray debugger break-in only when the break is proven to be a plain break-in. It returns at once, without resuming, when the target is already halted. It returns the output that breakpoint commands printed while the target ran.
- First-chance exceptions are left to the engine's event filters instead of being passed back to the guest, so a hard-coded breakpoint or an assertion in a driver halts the target and is reported.
- The execution status is mapped from DbgEng's `DEBUG_STATUS` by name. The earlier cast between two enums with different numbers read a lost session (`DEBUG_STATUS_NO_DEBUGGEE`) as running.
- `kd_execute` splits a compound command on `;` outside double quotes and checks the command name of every part against a longer list, which includes `tb`, `tct`, `pct` and `qd`. It sets `DEBUG_ENGOPT_DISABLE_EXECUTION_COMMANDS` while the command runs and reads the execution status afterwards. It refuses host-side commands with an allowlist of dot-commands (see above) and caps its timeout at 300 s. A command that times out is interrupted.
- `kd_connect` takes no connection string; it uses the configured transport. It no longer needs the guest to answer on SSH, only that the host does not report the VM as off, paused or saved.
- `.process /i` support: `kd_continue` runs the target until the context-switch break, skips stale break-ins outside the requested process, and leaves the target halted in the new process context.
- A per-logon-session mutex allows one kernel debug session across server instances.
- `dbgeng.dll` is loaded by full path from `Host.DebuggersPath` or the installed Windows Kit, and the KDNET key is redacted in logs. On connect the server sets symbol options, runs a deferred `.reload` instead of `.reload /f`, and turns off `.shell` in the engine.
- The precondition gate no longer probes the VM while the kernel debugger holds it halted, and every state mutation is serialized with the refresh.

User mode:

- Frida: one `umd_frida` tool replaces `umd_frida_attach`, `umd_frida` and `umd_frida_skill`; each `eval` and `inject` names its target. `start_server` starts frida-server outside the SSH session. An optional token reaches frida in `FRIDA_TOKEN`. The background buffer is limited by characters.
- dbgsrv: one `umd_dbgsrv` tool replaces `umd_dbgsrv_connect`, `umd_dbgsrv_execute` and `umd_dbgsrv_skill`; it connects only to the configured guest. cdb.exe gets `-noshell` and `-y <symbol path>`, and an optional password.
- `guest_list_processes` and `guest_kill_process` are removed: `guest_run_command` runs `tasklist` and `taskkill`.
- Frida, frida-ps and cdb are started by full path with argument lists. Upstream built a command-line string, so a quote in a process name or command could add options.
- TTD: the output folder option is placed before `-launch`; upstream placed it after the target, where TTD passes it to the target. A recording starts outside the SSH session, and the call returns at once. `stop` uses `TTD.exe -stop all` instead of killing the recorder. The `umd_ttd_query` stub (not implemented upstream) is removed.
- The help texts use the configured paths and ports and include the firewall scoping. Frida, dbgsrv and TTD are off by default.

Server and configuration:

- Configuration: `WINDBG_HYPERV_MCP_CONFIG`, `WINDBG_HYPERV_MCP_*` environment overrides, nothing read from the current directory, no configuration file copied into the build output, validation at startup, unused settings removed.
- Every host program is started by its full path; `NoDefaultCurrentDirectoryInExePath=1` is set at startup.
- Every tool result is bounded by `Limits.MaxOutputChars`, and a longer one is saved in full to a file. Refusals and failures set `isError`. Every tool sets all four annotation hints. Parameters with fixed values are enums. The input schemas do not repeat the tool name and description.
- The server instructions no longer contain the guest password and the KDNET key (the upstream instructions printed both) and no longer repeat the tool catalog. They state the policies in effect.
- Tool groups are registered by policy (`Policy.KernelDebug`, `Tools.*`).
- Host transfer path policy, host-side debugger command filter, `ssh -o IdentitiesOnly=yes`, and a configurable `StrictHostKeyChecking`.
- Upstream bugs fixed: session cleanup used `Dispose()`, which does nothing on the second call (now repeatable resets), and `umd_frida` checked only that the guest was reachable, not that a process was selected (now each `eval` and `inject` names its target).
- Retargeted from .NET 8 to .NET 10.
- Tests: new tests for the items above; `UnitTest1.cs` renamed to `SystemStateTests.cs`; tests that only checked constants removed.
- Documentation rewritten: this README and a new [architecture.md](architecture.md) that describes the code as it is. The upstream planning document is in the upstream repository.

## Related projects

Other repositories by the same author:

- [binja-agent-mcp](https://github.com/y637F9QQ2x/binja-agent-mcp): an MCP server for Binary Ninja, built for LLM agents.
- [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab): PowerShell scripts for a headless Hyper-V lab, with VM control that needs no elevation and guest commands over SSH as an administrator or as a standard user. This server uses its host tasks and its guest SSH setup.
- [win-agent-probes](https://github.com/y637F9QQ2x/win-agent-probes): PowerShell probes for Windows security research; each prints one JSON document.
- [winremote-session-ext](https://github.com/y637F9QQ2x/winremote-session-ext): an extension for winremote-mcp that reports the Windows logon session the server runs in and restricts how its HTTP endpoint can be exposed.

The author's blog: [y637f9qq2x.com](https://y637f9qq2x.com).

## Credits and license

windbg-hyperv-mcp is a modified version of [windbg-mcp](https://github.com/memoryforensics1/windbg-mcp) by memoryforensics1 (MIT license, commit `9a5f693505dac7cdc8d20622681ff4d764e5ca43`). The Hyper-V port and later changes are by Kazuma Matsumoto ([y637F9QQ2x](https://github.com/y637F9QQ2x)); [Changes from upstream](#changes-from-upstream) lists them.

- Dependencies, restored from NuGet and not included in this repository, with the license each package states: [ClrDebug](https://github.com/lordmilko/ClrDebug) 0.3.4 by lordmilko (MIT; DbgEng COM interop), [ModelContextProtocol](https://github.com/modelcontextprotocol/csharp-sdk) 0.1.0-preview.12 (MIT), Microsoft.Extensions.* 10.0.3 (MIT), and for the tests xUnit 2.5.3 and xunit.runner.visualstudio 2.5.3 (Apache-2.0) and Microsoft.NET.Test.Sdk 17.8.0 (MIT). Check each package's license before you redistribute binaries.
- External tools used at run time and not included: Debugging Tools for Windows (`dbgeng.dll`, `cdb.exe`, `dbgsrv.exe`), Windows OpenSSH, Frida, TTD.

License: MIT. See [LICENSE](LICENSE); it keeps the upstream copyright notice.

WinDbg, Hyper-V and Windows are trademarks of Microsoft.
