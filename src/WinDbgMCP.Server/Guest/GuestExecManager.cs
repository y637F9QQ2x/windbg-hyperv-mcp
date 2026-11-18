using System.Text;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest.Models;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.Security;

namespace WinDbgMCP.Server.Guest;

/// <summary>
/// Guest command execution and file transfer over key-based SSH / SCP (through LabHost).
/// SSH returns stdout, stderr and the exit code directly, so no temporary files are used in the guest.
/// Commands run as Vm.GuestUsername, which is normally a guest administrator, in the guest's OpenSSH
/// default shell, which must be cmd.exe (the Windows OpenSSH default).
/// </summary>
public sealed class GuestExecManager
{
    private readonly LabHost _lab;
    private readonly IReadOnlyList<string> _transferRoots;
    private readonly int _defaultTimeoutSeconds;
    private readonly ILogger<GuestExecManager> _logger;

    public GuestExecManager(LabHost lab, ServerConfig config, ILogger<GuestExecManager> logger)
    {
        _lab = lab;
        _transferRoots = HostPathPolicy.EffectiveRoots(config.Policy.HostTransferRoots);
        _defaultTimeoutSeconds = config.Timeouts.GuestCommandSeconds;
        _logger = logger;
    }

    /// <summary>
    /// The command line sent to the guest's shell. "chcp 65001" switches the console to UTF-8 first, so
    /// non-ASCII output is not garbled; the optional working directory is entered with cd /d.
    /// </summary>
    public static string BuildGuestCommand(string command, string? workingDirectory)
    {
        var inner = string.IsNullOrEmpty(workingDirectory) ? command : $"cd /d \"{workingDirectory}\" && {command}";
        return "chcp 65001>nul & " + inner;
    }

    /// <summary>
    /// A guest command line that starts <paramref name="commandLine"/> outside the SSH session, through WMI
    /// (Win32_Process.Create). A program started directly from the SSH session (for example with start /b)
    /// keeps the session's output pipes open, so ssh does not return, and Windows OpenSSH ends the session's
    /// processes when the session closes. The PowerShell script is passed base64-encoded, so no quoting of
    /// <paramref name="commandLine"/> is needed beyond doubling its single quotes inside the script.
    /// </summary>
    public static string BuildDetachedStart(string commandLine)
    {
        var script =
            "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '" +
            commandLine.Replace("'", "''") + "' }; " +
            "'Win32_Process.Create ReturnValue=' + $r.ReturnValue + ' ProcessId=' + $r.ProcessId";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded;
    }

    /// <summary>Run a command in the guest through sshd and capture its output.</summary>
    public async Task<GuestCommandResult> RunCommandAsync(
        string command,
        string? workingDirectory = null,
        int? timeoutSeconds = null,
        CancellationToken ct = default,
        string? logAs = null)
    {
        if (workingDirectory?.Contains('"') == true)
            return GuestCommandResult.Failed("workingDirectory must not contain a double quote.");

        var seconds = Math.Clamp(timeoutSeconds ?? _defaultTimeoutSeconds, 1, 3600);
        _logger.LogDebug("Guest exec (ssh): {Cmd} (timeout={Timeout}s)", logAs ?? Redact.CommandLine(command), seconds);

        try
        {
            var r = await _lab.RunGuestCommandAsync(BuildGuestCommand(command, workingDirectory),
                TimeSpan.FromSeconds(seconds), ct, logAs);
            return GuestCommandResult.Ok(r.ExitCode, r.Stdout.Trim(), r.Stderr.Trim() + ShellHint(r.Stderr));
        }
        catch (TimeoutException)
        {
            return GuestCommandResult.Failed(
                $"The command timed out after {seconds} s. It may still be running in the guest. Check with " +
                "guest_run_command(\"tasklist\") and end it with guest_run_command(\"taskkill /F /PID <pid>\").");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Guest command failed: {Cmd}", logAs ?? Redact.CommandLine(command));
            return GuestCommandResult.Failed($"Guest command failed: {ex.Message} Check get_system_state.");
        }
    }

    /// <summary>Start a program in the guest that outlives the SSH session (see <see cref="BuildDetachedStart"/>).</summary>
    public Task<GuestCommandResult> StartDetachedAsync(string commandLine, CancellationToken ct, string? logAs = null)
        => RunCommandAsync(BuildDetachedStart(commandLine), null, 30, ct,
            "start detached: " + (logAs ?? Redact.CommandLine(commandLine)));

    /// <summary>
    /// The guest's OpenSSH default shell is PowerShell when cmd.exe syntax fails like this. Then every guest
    /// command fails, so say how to fix it.
    /// </summary>
    internal static string ShellHint(string? stderr) =>
        stderr != null && (stderr.Contains("AmpersandNotAllowed", StringComparison.Ordinal) ||
                           stderr.Contains("The ampersand (&) character is not allowed", StringComparison.Ordinal))
            ? "\n[windbg-hyperv-mcp] The guest's OpenSSH default shell looks like PowerShell; this server needs cmd.exe. " +
              @"In the guest, remove the DefaultShell value under HKLM\SOFTWARE\OpenSSH, or set it to C:\Windows\System32\cmd.exe."
            : "";

    /// <summary>Copy a host file to the guest (scp). The host path must pass <see cref="HostPathPolicy"/>.</summary>
    public async Task<string> CopyFileToGuestAsync(string hostPath, string guestPath, CancellationToken ct = default)
    {
        var refusal = HostPathPolicy.Check(hostPath, _transferRoots, out var full);
        if (refusal != null)
            throw new HostPathRefusedException(refusal);
        if (!File.Exists(full))
            throw new FileNotFoundException($"Host file not found: {HostPathPolicy.ForDisplay(full)}");

        var result = await _lab.CopyFileToGuestAsync(full, guestPath, ct);
        if (!result.Success)
            throw new InvalidOperationException($"File transfer failed: {Detail(result)}");

        var fileSize = new FileInfo(full).Length;
        return $"Copied {HostPathPolicy.ForDisplay(full)} to guest:{guestPath} ({fileSize:N0} bytes).";
    }

    /// <summary>Copy a guest file to the host (scp). The host path must pass <see cref="HostPathPolicy"/>.</summary>
    public async Task<string> CopyFileFromGuestAsync(string guestPath, string hostPath, CancellationToken ct = default)
    {
        var refusal = HostPathPolicy.Check(hostPath, _transferRoots, out var full);
        if (refusal != null)
            throw new HostPathRefusedException(refusal);
        if (Directory.Exists(full))
            throw new InvalidOperationException($"The host path is a directory; give a file name: {HostPathPolicy.ForDisplay(full)}");

        var hostDir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(hostDir) && !Directory.Exists(hostDir))
            Directory.CreateDirectory(hostDir);

        var result = await _lab.CopyFileFromGuestAsync(guestPath, full, ct);
        if (!result.Success)
            throw new InvalidOperationException($"File transfer failed: {Detail(result)}");

        if (!File.Exists(full))
            throw new InvalidOperationException($"The transfer finished but the file is not at {HostPathPolicy.ForDisplay(full)}.");

        var fileSize = new FileInfo(full).Length;
        return $"Copied guest:{guestPath} to {HostPathPolicy.ForDisplay(full)} ({fileSize:N0} bytes).";
    }

    private static string Detail(ProcessResult r)
    {
        if (!string.IsNullOrWhiteSpace(r.Stderr)) return r.Stderr.Trim();
        if (!string.IsNullOrWhiteSpace(r.Stdout)) return r.Stdout.Trim();
        return $"exit code {r.ExitCode}";
    }
}

/// <summary>A host path that <see cref="HostPathPolicy"/> refused.</summary>
public sealed class HostPathRefusedException : Exception
{
    public HostPathRefusedException(string message) : base(message) { }
}
