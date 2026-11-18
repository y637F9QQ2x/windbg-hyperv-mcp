using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.Security;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.HyperV;

/// <summary>
/// The host side of the lab, for a server that runs NON-elevated. It never calls the Hyper-V cmdlets
/// (a non-elevated process cannot):
///
///   * VM lifecycle (start, stop, turn off, pause, resume, status) runs the on-demand scheduled tasks of
///     the host automation, hyperv-lpe-lab (see <see cref="LabTaskClient"/>). An administrator registers
///     them once. They run a fixed worker script with a fixed action and take no parameters.
///   * Guest commands and file transfers use key-based SSH and SCP to the account in Vm.GuestUsername.
///     That needs no host privilege.
///   * "Is the guest up?" is answered by one TCP connect to the guest SSH port, which is exactly the
///     precondition of the guest tools. It cannot tell Off from Paused, booting or network down; the
///     Status task (get_system_state with queryHost=true) reports the real Hyper-V state.
/// </summary>
public sealed class LabHost
{
    private static readonly Encoding Utf8 = new UTF8Encoding(false);

    private readonly string _guestUser;
    private readonly string _guestIp;
    private readonly string _hostKey;
    private readonly string _knownHosts;
    private readonly string _strictHostKeyChecking;
    private readonly string _sshPath;
    private readonly string _scpPath;
    private readonly LabTaskClient _lab;
    private readonly TimeoutConfig _timeouts;
    private readonly ILogger<LabHost> _logger;

    // One lifecycle task at a time from this server.
    private readonly SemaphoreSlim _taskLock = new(1, 1);

    public LabHost(ServerConfig config, ILogger<LabHost> logger)
    {
        _guestUser = config.Vm.GuestUsername;
        _guestIp = config.Vm.GuestIpAddress;
        _hostKey = ConfigValidator.EffectivePrivateKeyPath(config.Vm.HostPrivateKeyPath);
        _knownHosts = ConfigValidator.EffectiveKnownHostsPath(config.Vm.KnownHostsFile);
        _strictHostKeyChecking = config.Vm.StrictHostKeyChecking;
        _sshPath = ToolPaths.Ssh(config.Host);
        _scpPath = ToolPaths.Scp(config.Host);
        _timeouts = config.Timeouts;
        _logger = logger;

        if (!ConfigValidator.IsValidLabName(config.Vm.Lab) || !ConfigValidator.IsValidGuestUserName(_guestUser) ||
            !ConfigValidator.IsValidIpAddress(_guestIp))
            throw new InvalidOperationException("Invalid Vm.Lab, Vm.GuestUsername or Vm.GuestIpAddress (run the config validation first).");

        _lab = new LabTaskClient(config.Vm.Lab, ConfigValidator.EffectiveInstallRoot(config.Vm.InstallRoot), logger);

        if (!File.Exists(_hostKey))
            _logger.LogWarning("SSH private key {Key} does not exist; guest operations will fail until it does.", _hostKey);
        if (!File.Exists(_sshPath) || !File.Exists(_scpPath))
            _logger.LogWarning("{Ssh} or {Scp} does not exist. Install the Windows OpenSSH client, or set Host.OpenSshPath.", _sshPath, _scpPath);
    }

    // ===============================================================
    //  LIFECYCLE (lab tasks)
    // ===============================================================

    public Task<VmResult> StartAsync(CancellationToken ct = default) => RunLabTaskAsync("Start", _timeouts.VmStartSeconds, ct);

    /// <summary>Stop: guest shutdown. TurnOff: power off.</summary>
    public Task<VmResult> StopAsync(bool turnOff, CancellationToken ct = default)
        => RunLabTaskAsync(turnOff ? "TurnOff" : "Stop", _timeouts.VmStopSeconds, ct);

    public Task<VmResult> PauseAsync(CancellationToken ct = default) => RunLabTaskAsync("Pause", _timeouts.VmPauseResumeSeconds, ct);

    public Task<VmResult> ResumeAsync(CancellationToken ct = default) => RunLabTaskAsync("Resume", _timeouts.VmPauseResumeSeconds, ct);

    /// <summary>The Hyper-V view of the VM (state, heartbeat, uptime, IPv4) from the Status task.</summary>
    public Task<VmResult> QueryHostStatusAsync(CancellationToken ct = default) => RunLabTaskAsync("Status", _timeouts.VmStatusSeconds, ct);

    private async Task<VmResult> RunLabTaskAsync(string action, int waitSeconds, CancellationToken ct)
    {
        // A short wait for the lock, so a call never waits for another task and then for its own result.
        if (!await _taskLock.WaitAsync(TimeSpan.FromSeconds(2), ct))
            return VmResult.Failed("Another lifecycle task from this server is still running. Call get_system_state, then retry.");
        try { return await _lab.RunAsync(action, waitSeconds, ct); }
        finally { _taskLock.Release(); }
    }

    // ===============================================================
    //  REACHABILITY (one TCP connect; no host privilege)
    // ===============================================================

    /// <summary>TCP 22 reachable = guest up, networked and sshd listening (the guest-operation precondition).</summary>
    public async Task<bool> ProbeGuestSshAsync(CancellationToken ct = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _timeouts.VmStateQuerySeconds)));
        try
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            // The cancellation-token overload aborts and observes the pending connect on timeout.
            await tcp.ConnectAsync(System.Net.IPAddress.Parse(_guestIp), 22, timeoutCts.Token);
            return tcp.Connected;
        }
        catch
        {
            return false;
        }
    }

    // ===============================================================
    //  GUEST OPERATIONS (key-based SSH / SCP)
    // ===============================================================

    /// <summary>
    /// Run <paramref name="remoteCommand"/> in the guest's default shell over SSH. <paramref name="logAs"/>
    /// replaces the command in the debug log (for a command line that carries a secret).
    /// </summary>
    public async Task<ProcessResult> RunGuestCommandAsync(string remoteCommand, TimeSpan timeout, CancellationToken ct,
        string? logAs = null)
    {
        var args = new List<string>(SshBaseArgs(_hostKey, _knownHosts, _strictHostKeyChecking))
        {
            _guestUser + "@" + _guestIp,
            remoteCommand,
        };
        var shown = logAs ?? Redact.CommandLine(remoteCommand);
        _logger.LogDebug("ssh {User}@{Ip}: {Cmd}", _guestUser, _guestIp, shown.Length > 200 ? shown[..200] + "..." : shown);

        var r = await ProcessRunner.RunAsync(_sshPath, args, timeout, ct, "guest SSH command", encoding: Utf8);
        // ssh exits 255 on its own connect or auth failure, but it also passes through the remote command's
        // exit code, so a guest program that exits 255 looks the same. Treat 255 as a transport failure only
        // when it looks like one: no stdout (the remote command never ran) and an ssh diagnostic on stderr.
        if (r.ExitCode == 255 && LooksLikeSshTransportFailure(r))
            throw new InvalidOperationException(
                "Guest SSH transport failed (exit 255): " + Err(r) +
                ". The VM may be down or unreachable, or this host's public key is not installed for the guest account." +
                KnownHostsHint(r));
        return r;
    }

    public Task<ProcessResult> CopyFileToGuestAsync(string hostPath, string guestPath, CancellationToken ct = default)
        => RunScpAsync(hostPath, RemoteScpPath(_guestUser, _guestIp, guestPath), ct);

    public Task<ProcessResult> CopyFileFromGuestAsync(string guestPath, string hostPath, CancellationToken ct = default)
        => RunScpAsync(RemoteScpPath(_guestUser, _guestIp, guestPath), hostPath, ct);

    private Task<ProcessResult> RunScpAsync(string src, string dst, CancellationToken ct)
    {
        var args = new List<string>(SshBaseArgs(_hostKey, _knownHosts, _strictHostKeyChecking)) { src, dst };
        _logger.LogDebug("scp {Src} to {Dst}", src, dst);
        return ProcessRunner.RunAsync(_scpPath, args, TimeSpan.FromSeconds(_timeouts.GuestFileTransferSeconds), ct,
            "guest SCP transfer", encoding: Utf8);
    }

    // ===============================================================
    //  ARGUMENTS (static, tested)
    // ===============================================================

    /// <summary>scp remote endpoint user@ip:path, with forward slashes (Windows OpenSSH accepts them).</summary>
    internal static string RemoteScpPath(string user, string ip, string guestPath)
        => user + "@" + ip + ":" + guestPath.Replace('\\', '/');

    /// <summary>
    /// Options for ssh.exe and scp.exe: key-only authentication with the configured key and no other
    /// identities (IdentitiesOnly), no password prompt (BatchMode), and a known_hosts file used only for this
    /// guest. ssh expands % tokens in the key path, so a literal % is doubled. The known_hosts path is quoted,
    /// because ssh reads UserKnownHostsFile as a list separated by spaces; ConfigValidator refuses the
    /// characters that ssh would read differently inside the quotes.
    /// </summary>
    internal static IReadOnlyList<string> SshBaseArgs(string hostKey, string knownHosts, string strictHostKeyChecking) => new[]
    {
        "-i", hostKey.Replace("%", "%%"),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=" + strictHostKeyChecking,
        "-o", "UserKnownHostsFile=\"" + knownHosts + "\"",
        "-o", "ConnectTimeout=10",
    };

    private static string Err(ProcessResult r)
    {
        if (!string.IsNullOrWhiteSpace(r.Stderr)) return r.Stderr.Trim();
        if (!string.IsNullOrWhiteSpace(r.Stdout)) return r.Stdout.Trim();
        return "exit code " + r.ExitCode;
    }

    private static readonly string[] SshTransportMarkers =
    {
        "ssh:", "connect to host", "Connection refused", "Connection timed out", "Connection closed",
        "Permission denied", "kex_exchange", "Host key verification failed", "Could not resolve hostname",
        "No route to host", "Network is unreachable", "Operation timed out", "Too many authentication failures",
    };

    internal static bool LooksLikeSshTransportFailure(ProcessResult r)
    {
        if (!string.IsNullOrWhiteSpace(r.Stdout)) return false;   // the remote command produced output, so it ran
        var e = r.Stderr ?? string.Empty;
        foreach (var m in SshTransportMarkers)
            if (e.Contains(m, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>A reinstalled guest has a new host key: say how to reset the pinned one.</summary>
    internal static string KnownHostsHint(ProcessResult r) =>
        (r.Stderr ?? "").Contains("Host key verification failed", StringComparison.OrdinalIgnoreCase) ||
        (r.Stderr ?? "").Contains("REMOTE HOST IDENTIFICATION HAS CHANGED", StringComparison.OrdinalIgnoreCase)
            ? " If the guest was reinstalled, its host key changed: remove its line from the known_hosts file " +
              "(ssh-keygen -R <guest-ip> -f <Vm.KnownHostsFile>) after you check the new key."
            : "";
}
