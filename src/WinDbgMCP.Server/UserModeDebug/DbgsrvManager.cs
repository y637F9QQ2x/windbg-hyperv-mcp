using System.Globalization;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.Security;

namespace WinDbgMCP.Server.UserModeDebug;

/// <summary>
/// Noninvasive user-mode inspection through dbgsrv.exe in the guest, driven by cdb.exe on the host as a
/// separate process. There is no connection state: every command is one cdb.exe run,
///   cdb -premote tcp:port=P,server=IP[,password=X] -noshell -y SYMBOLS -pv -p PID -c ".echo START; command; .echo END; q"
/// against the configured guest address and port only.
///
/// Why a separate process: DbgEng keeps per-process global state. While the kernel session is open in this
/// process, a second in-process client can connect to a process server, but its wait after AttachProcess does
/// not complete (upstream's DbgsrvManager.cs states this in its header comment). A child cdb.exe has its own
/// DbgEng state.
///
/// -pv attaches noninvasively and suspends the target's threads while cdb.exe is attached, that is for the
/// duration of one command. -pvr would leave them running, at the cost of reads that can be inconsistent; this
/// server uses -pv so stacks and memory are read from a stopped process. -noshell makes cdb.exe itself refuse
/// .shell, in addition to HostCommandGuard.
/// </summary>
public sealed class DbgsrvManager
{
    private const string StartMarker = "<<<START>>>";
    private const string EndMarker = "<<<END>>>";

    private readonly ServerConfig _config;
    private readonly ILogger<DbgsrvManager> _logger;

    public DbgsrvManager(ServerConfig config, ILogger<DbgsrvManager> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>The -premote transport string for the configured guest.</summary>
    public static string BuildTransport(string guestIp, int port, string? password) =>
        $"tcp:port={port.ToString(CultureInfo.InvariantCulture)},server={guestIp}" +
        (string.IsNullOrEmpty(password) ? "" : ",password=" + password);

    /// <summary>The cdb.exe argument list for one command (public for tests).</summary>
    public static IReadOnlyList<string> BuildCdbArguments(string transport, string symbolPath, uint pid, string command) => new[]
    {
        "-premote", transport,
        "-noshell",
        "-y", symbolPath,
        "-pv", "-p", pid.ToString(CultureInfo.InvariantCulture),
        "-c", $".echo {StartMarker}; {command}; .echo {EndMarker}; q",
    };

    /// <summary>The guest command line that start_server runs (through WMI, outside the SSH session).</summary>
    public static string BuildServerCommandLine(string dbgsrvPath, int port, string? password) =>
        $"\"{dbgsrvPath}\" -t tcp:port={port.ToString(CultureInfo.InvariantCulture)}" +
        (string.IsNullOrEmpty(password) ? "" : ",password=" + password);

    /// <summary>Run <paramref name="command"/> against guest process <paramref name="pid"/>.</summary>
    public async Task<DbgsrvResult> ExecuteAsync(uint pid, string command, int timeoutSeconds, CancellationToken ct)
    {
        // The command travels on the cdb.exe command line inside -c "...". A double quote would end that
        // argument, so it is refused instead of being passed on.
        if (command.Contains('"'))
            return new DbgsrvResult(false, "Commands that contain a double quote (\") are not supported by umd_dbgsrv, because " +
                                           "the command is passed inside a quoted cdb.exe argument.");

        var cdb = ToolPaths.Cdb(_config.Host);
        if (cdb == null)
            return new DbgsrvResult(false, "cdb.exe was not found. Install Debugging Tools for Windows (a Windows SDK feature) " +
                                           "or set Host.DebuggersPath to the folder with dbgeng.dll and cdb.exe.");

        var args = BuildCdbArguments(
            BuildTransport(_config.Vm.GuestIpAddress, _config.Guest.DbgsrvPort, _config.Guest.DbgsrvPassword),
            Environment.ExpandEnvironmentVariables(_config.KernelDebug.SymbolPath), pid, command);
        _logger.LogDebug("Running: cdb {Args}", Redact.Arguments(args));

        ProcessResult r;
        try
        {
            r = await ProcessRunner.RunAsync(cdb, args, TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 1, 600)), ct, "cdb.exe");
        }
        catch (TimeoutException ex)
        {
            return new DbgsrvResult(false, ex.Message + " Try a smaller command (\"lm\" before \"~*k\").");
        }

        // No markers: cdb.exe never ran the command (it could not reach dbgsrv, or could not attach).
        var output = ExtractOutput(r.Stdout);
        if (output == null)
            return new DbgsrvResult(false, FailureText(r.Stdout, r.ExitCode));

        return new DbgsrvResult(true, output.Length == 0 ? "(no output)" : output);
    }

    /// <summary>
    /// The result of a run without markers: the last 2,000 characters of cdb's output and what to check. The
    /// output goes through <see cref="Redact.CommandLine"/> first, because cdb can print the -premote
    /// transport, which carries the dbgsrv password. Redacting before the cut means the cut cannot leave the
    /// end of a password behind without its "password=" name.
    /// </summary>
    internal static string FailureText(string stdout, int exitCode)
    {
        var tail = Redact.CommandLine(stdout.Trim());
        if (tail.Length > 2000) tail = "..." + tail[^2000..];
        return (tail.Length == 0 ? $"cdb.exe exited with code {exitCode} and printed nothing." : tail) +
               "\nCould not reach dbgsrv or attach. Check that dbgsrv runs in the guest (umd_dbgsrv(action='start_server')), " +
               "that the guest firewall allows the port from this host, that Guest.DbgsrvPassword matches (a wrong one " +
               "gives error 0x80004005), and the PID.";
    }

    /// <summary>
    /// The text between the markers ("" when the command printed nothing), or null when the markers are missing.
    /// Only a marker at the start of a line counts: cdb also echoes the initial command line, which contains
    /// both markers inside one line, before it runs it.
    /// </summary>
    public static string? ExtractOutput(string fullOutput)
    {
        var starts = System.Text.RegularExpressions.Regex.Matches(fullOutput, "(?m)^" + StartMarker + @"[ \t]*\r?$");
        if (starts.Count == 0) return null;
        var startIdx = starts[^1].Index + starts[^1].Length;

        var end = System.Text.RegularExpressions.Regex.Match(fullOutput[startIdx..], "(?m)^" + EndMarker);
        if (!end.Success) return null;

        return fullOutput.Substring(startIdx, end.Index).Trim();
    }
}

public sealed record DbgsrvResult(bool Success, string Output);
