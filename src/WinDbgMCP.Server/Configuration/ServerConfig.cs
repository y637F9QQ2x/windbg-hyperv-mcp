namespace WinDbgMCP.Server.Configuration;

/// <summary>
/// Root configuration model. Bound once at startup from the file named by the WINDBG_HYPERV_MCP_CONFIG
/// environment variable (or appsettings.json next to the executable). A restart applies changes.
/// </summary>
public sealed class ServerConfig
{
    public VmConfig Vm { get; set; } = new();
    public KernelDebugConfig KernelDebug { get; set; } = new();
    public GuestConfig Guest { get; set; } = new();
    public HostConfig Host { get; set; } = new();
    public ToolsConfig Tools { get; set; } = new();
    public PolicyConfig Policy { get; set; } = new();
    public LimitsConfig Limits { get; set; } = new();
    public TimeoutConfig Timeouts { get; set; } = new();
}

public sealed class VmConfig
{
    /// <summary>Hyper-V VM name. Shown in get_system_state; the lab tasks decide which VM they control.</summary>
    public string VmName { get; set; } = string.Empty;

    /// <summary>Static IPv4 address of the guest on the host's internal switch (SSH, Frida, dbgsrv).</summary>
    public string GuestIpAddress { get; set; } = string.Empty;

    /// <summary>Guest account used for key-based SSH by the guest_* tools. Normally a guest administrator.</summary>
    public string GuestUsername { get; set; } = string.Empty;

    /// <summary>Host private key for SSH to the guest. Empty: %USERPROFILE%\.ssh\id_ed25519.</summary>
    public string HostPrivateKeyPath { get; set; } = string.Empty;

    /// <summary>known_hosts file used only for the guest. Empty: %USERPROFILE%\.ssh\windbg-hyperv-mcp_known_hosts.</summary>
    public string KnownHostsFile { get; set; } = string.Empty;

    /// <summary>OpenSSH StrictHostKeyChecking value: "accept-new" (trust on first use, the default) or "yes".</summary>
    public string StrictHostKeyChecking { get; set; } = "accept-new";

    /// <summary>
    /// Lab name used at host setup (Install-HvLab.ps1 -Lab). The lifecycle tasks are
    /// \HyperVLpeLab\&lt;Lab&gt;\&lt;Action&gt;. 1-32 letters, digits or hyphens.
    /// </summary>
    public string Lab { get; set; } = string.Empty;

    /// <summary>hyperv-lpe-lab install root. Empty: %ProgramData%\HyperVLpeLab.</summary>
    public string InstallRoot { get; set; } = string.Empty;
}

public sealed class KernelDebugConfig
{
    public const string DefaultSymbolPath =
        @"srv*%LOCALAPPDATA%\windbg-hyperv-mcp\symbols*https://msdl.microsoft.com/download/symbols";

    /// <summary>"kdnet" or "serial".</summary>
    public string Transport { get; set; } = "kdnet";
    public KdnetConfig Kdnet { get; set; } = new();
    public SerialConfig Serial { get; set; } = new();

    /// <summary>Symbol path for kd_* and for the cdb.exe runs of umd_dbgsrv. Environment variables are expanded.</summary>
    public string SymbolPath { get; set; } = DefaultSymbolPath;
}

public sealed class KdnetConfig
{
    public int Port { get; set; } = 50000;

    /// <summary>The key that bcdedit /dbgsettings printed in the guest. A secret: it is never logged or returned.</summary>
    public string Key { get; set; } = string.Empty;
}

public sealed class SerialConfig
{
    /// <summary>Local named pipe of the VM's COM port (\\.\pipe\name).</summary>
    public string PipeName { get; set; } = @"\\.\pipe\com_1";
}

public sealed class GuestConfig
{
    public int FridaPort { get; set; } = 27042;
    public int DbgsrvPort { get; set; } = 5064;

    /// <summary>frida-server path in the guest (umd_frida start_server).</summary>
    public string FridaServerPath { get; set; } = @"C:\Tools\frida-server.exe";

    /// <summary>dbgsrv.exe path in the guest (umd_dbgsrv start_server).</summary>
    public string DbgsrvPath { get; set; } = @"C:\Tools\DbgSrv\dbgsrv.exe";

    /// <summary>TTD.exe path in the guest (umd_ttd).</summary>
    public string TtdPath { get; set; } = @"C:\Tools\TTD\TTD.exe";

    /// <summary>Guest directory for TTD traces.</summary>
    public string TtdOutputDirectory { get; set; } = @"C:\TTD_Traces";

    /// <summary>
    /// Optional frida-server token. When set, start_server starts frida-server with --token, and frida.exe and
    /// frida-ps.exe get it in the FRIDA_TOKEN environment variable. Empty: frida-server accepts any client.
    /// </summary>
    public string FridaToken { get; set; } = string.Empty;

    /// <summary>
    /// Optional dbgsrv password (at most 12 letters or digits). When set, start_server starts dbgsrv with it and
    /// cdb.exe sends it. Empty: dbgsrv accepts any client.
    /// </summary>
    public string DbgsrvPassword { get; set; } = string.Empty;
}

public sealed class HostConfig
{
    /// <summary>
    /// Folder with dbgeng.dll and cdb.exe (Debugging Tools for Windows). Empty: the x64 debuggers of the
    /// installed Windows Kit (KitsRoot10 in the registry), then %ProgramFiles(x86)%\Windows Kits\10\Debuggers\x64.
    /// </summary>
    public string DebuggersPath { get; set; } = string.Empty;

    /// <summary>Folder with frida.exe and frida-ps.exe. Empty: the fully qualified PATH entries.</summary>
    public string FridaToolsPath { get; set; } = string.Empty;

    /// <summary>Folder with ssh.exe and scp.exe. Empty: %SystemRoot%\System32\OpenSSH.</summary>
    public string OpenSshPath { get; set; } = string.Empty;
}

public sealed class ToolsConfig
{
    /// <summary>Register umd_frida. Off by default: it needs frida-tools on the host and frida-server in the guest.</summary>
    public bool Frida { get; set; } = false;

    /// <summary>Register umd_dbgsrv. Off by default: it needs dbgsrv.exe in the guest.</summary>
    public bool Dbgsrv { get; set; } = false;

    /// <summary>Register umd_ttd. Off by default: it needs TTD.exe in the guest.</summary>
    public bool Ttd { get; set; } = false;
}

public sealed class PolicyConfig
{
    /// <summary>
    /// "Attended" (default): the kd_* tools are registered and the server instructions tell the
    /// model to use them only while an operator watches. "Enabled": registered, no such text.
    /// "Disabled": the kd_* tools are not registered.
    /// </summary>
    public string KernelDebug { get; set; } = "Attended";

    /// <summary>
    /// Refuse debugger commands that act on the HOST in kd_execute and umd_dbgsrv. See README,
    /// "Debugger commands that act on the host".
    /// </summary>
    public bool BlockHostSideEffectCommands { get; set; } = true;

    /// <summary>
    /// Host folders that guest_transfer_* and umd_ttd retrieve may read from or write to, and where cut tool
    /// results are saved. "*" as the only entry disables the folder check. Environment variables are expanded.
    /// </summary>
    public List<string> HostTransferRoots { get; set; } = new();
}

public sealed class LimitsConfig
{
    public const int MinOutputChars = 8_000;
    public const int MaxOutputCharsLimit = 500_000;

    /// <summary>Longest tool result, in UTF-16 code units. A longer result is cut and saved to a file.</summary>
    public int MaxOutputChars { get; set; } = 48_000;
}

public sealed class TimeoutConfig
{
    // VM operations (seconds): how long a tool waits for the lab task's result before it reports "pending".
    public int VmStartSeconds { get; set; } = 45;
    public int VmStopSeconds { get; set; } = 30;
    public int VmPauseResumeSeconds { get; set; } = 10;
    public int VmStatusSeconds { get; set; } = 30;

    /// <summary>TCP connect timeout of the guest SSH (port 22) reachability probe.</summary>
    public int VmStateQuerySeconds { get; set; } = 3;

    // Kernel debug operations (seconds)
    public int KdConnectSeconds { get; set; } = 30;
    public int KdInitialBreakSeconds { get; set; } = 15;
    public int KdBreakSeconds { get; set; } = 10;
    public int KdStepSeconds { get; set; } = 10;

    // Guest operations (seconds): defaults; guest_run_command also takes its own timeoutSeconds.
    public int GuestCommandSeconds { get; set; } = 45;
    public int GuestFileTransferSeconds { get; set; } = 45;
}
