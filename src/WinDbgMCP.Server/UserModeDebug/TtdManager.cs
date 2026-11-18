using System.Globalization;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.Guest.Models;

namespace WinDbgMCP.Server.UserModeDebug;

/// <summary>
/// Time Travel Debugging recordings made by TTD.exe inside the guest (Guest.TtdPath). A recording runs until
/// the target exits or 'stop' ends it, so TTD.exe is started outside the SSH session (through WMI) and the
/// call returns at once. Traces are written to Guest.TtdOutputDirectory in the guest and can be copied to the
/// host for WinDbg. This server does not analyze traces. Starting a recording passes -accepteula to TTD.exe,
/// which accepts the TTD license terms on the operator's behalf (Tools.Ttd is off by default).
/// </summary>
public sealed class TtdManager
{
    private readonly GuestExecManager _guest;
    private readonly ILogger<TtdManager> _logger;
    private readonly string _ttdPath;
    private readonly string _outputDir;

    public TtdManager(GuestExecManager guest, ServerConfig config, ILogger<TtdManager> logger)
    {
        _guest = guest;
        _logger = logger;
        _ttdPath = config.Guest.TtdPath;
        _outputDir = config.Guest.TtdOutputDirectory;
    }

    public static string BuildLaunchCommandLine(string ttdPath, string outputDir, string targetPath, string arguments) =>
        $"\"{ttdPath}\" -accepteula -out \"{outputDir}\" -launch \"{targetPath}\" {arguments}".TrimEnd();

    public static string BuildAttachCommandLine(string ttdPath, string outputDir, uint pid) =>
        $"\"{ttdPath}\" -accepteula -out \"{outputDir}\" -attach {pid.ToString(CultureInfo.InvariantCulture)}";

    public async Task<string> RecordLaunchAsync(string targetPath, string arguments, CancellationToken ct)
    {
        if (targetPath.Contains('"'))
            throw new ArgumentException("The target path must not contain a double quote.");
        _logger.LogInformation("TTD record launch: {Target} {Args}", targetPath, arguments);
        await EnsureOutputDirectoryAsync(ct);
        var r = await _guest.StartDetachedAsync(BuildLaunchCommandLine(_ttdPath, _outputDir, targetPath, arguments), ct);
        return Started(r, $"{targetPath} under TTD");
    }

    public async Task<string> RecordAttachAsync(uint pid, CancellationToken ct)
    {
        _logger.LogInformation("TTD record attach to PID {Pid}", pid);
        await EnsureOutputDirectoryAsync(ct);
        var r = await _guest.StartDetachedAsync(BuildAttachCommandLine(_ttdPath, _outputDir, pid), ct);
        return Started(r, $"TTD on PID {pid}");
    }

    private string Started(GuestCommandResult r, string what)
    {
        if (!r.Success || r.ExitCode != 0 || !r.Stdout.Contains("ReturnValue=0", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Starting {what} failed: {r.Stdout} {r.Stderr}{r.ErrorMessage}".Trim() +
                $" Check that TTD.exe exists at {_ttdPath} in the guest (Guest.TtdPath).");
        return $"Started {what} ({r.Stdout.Trim()}). The recording runs until the target exits or " +
               "umd_ttd(action='stop'). Then use action='list' and action='retrieve'.";
    }

    private Task EnsureOutputDirectoryAsync(CancellationToken ct) =>
        _guest.RunCommandAsync($"if not exist \"{_outputDir}\" mkdir \"{_outputDir}\"", timeoutSeconds: 10, ct: ct);

    /// <summary>Stop active recordings (TTD.exe -stop all).</summary>
    public async Task<string> StopRecordingAsync(CancellationToken ct = default)
    {
        var result = await _guest.RunCommandAsync($"\"{_ttdPath}\" -stop all", timeoutSeconds: 30, ct: ct);
        if (result.Success && result.ExitCode == 0)
            return "TTD recordings stopped.";
        throw new InvalidOperationException($"TTD -stop failed: {result.Stdout} {result.Stderr}{result.ErrorMessage}".Trim());
    }

    public Task<string> RetrieveTraceAsync(string guestTracePath, string hostOutputPath, CancellationToken ct = default)
        => _guest.CopyFileFromGuestAsync(guestTracePath, hostOutputPath, ct);

    public async Task<string> ListTracesAsync(CancellationToken ct = default)
    {
        var result = await _guest.RunCommandAsync($"dir /b /s \"{_outputDir}\\*.run\" 2>nul", timeoutSeconds: 10, ct: ct);
        if (result.Success && !string.IsNullOrWhiteSpace(result.Stdout))
            return $"TTD traces in guest:{_outputDir}:\n{result.Stdout}";
        return $"No TTD trace files found in guest:{_outputDir}.";
    }
}
