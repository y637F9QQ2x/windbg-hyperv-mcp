using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.Security;

namespace WinDbgMCP.Server.UserModeDebug;

/// <summary>
/// Frida instrumentation through the frida-tools command line (frida.exe, frida-ps.exe) on the host,
/// connected to frida-server in the guest (-H guest:port). Every argument is passed through
/// ProcessStartInfo.ArgumentList, so a process name or script text cannot add frida options. Each eval and
/// inject names its target, so there is no attach state; the one background session (inject_bg) is the only
/// state this class keeps. Guest.FridaToken, when set, reaches frida in the FRIDA_TOKEN environment variable,
/// not on the command line.
/// </summary>
public sealed class FridaManager : IDisposable
{
    /// <summary>Background output kept between two collect_bg calls; older text is dropped first.</summary>
    public const int MaxBackgroundChars = 1_000_000;

    private readonly ServerConfig _config;
    private readonly ILogger<FridaManager> _logger;

    private readonly object _bgLock = new();
    private Process? _bgProcess;
    private string? _bgScriptPath;
    private string? _bgTarget;
    private readonly StringBuilder _bgOutput = new();
    private long _bgDropped;
    private bool _bgStarting;   // an inject_bg call holds the one background slot until it returns

    public FridaManager(ServerConfig config, ILogger<FridaManager> logger)
    {
        _config = config;
        _logger = logger;
    }

    private string GuestEndpoint => $"{_config.Vm.GuestIpAddress}:{_config.Guest.FridaPort.ToString(CultureInfo.InvariantCulture)}";

    /// <summary>The target of the running background session, or null.</summary>
    public string? BackgroundTarget
    {
        get
        {
            lock (_bgLock)
                return _bgProcess != null && !HasExited(_bgProcess) ? _bgTarget : null;
        }
    }

    // ===============================================================
    //  ARGUMENT LISTS (static, tested)
    // ===============================================================

    public static IReadOnlyList<string> TargetArgs(int? pid, string? processName) =>
        pid.HasValue
            ? new[] { "-p", pid.Value.ToString(CultureInfo.InvariantCulture) }
            : new[] { "-n", processName ?? throw new ArgumentException("pid or processName is required") };

    public static IReadOnlyList<string> BuildEvalArgs(string endpoint, int? pid, string? processName, string expression)
    {
        var a = new List<string> { "-H", endpoint };
        a.AddRange(TargetArgs(pid, processName));
        a.AddRange(new[] { "-q", "-t", "1", "-e", expression });
        return a;
    }

    public static IReadOnlyList<string> BuildInjectArgs(string endpoint, int? pid, string? processName, string scriptPath,
        int timeoutSeconds, bool eternalize)
    {
        var a = new List<string> { "-H", endpoint };
        a.AddRange(TargetArgs(pid, processName));
        a.AddRange(new[] { "-q", "-t", timeoutSeconds.ToString(CultureInfo.InvariantCulture) });
        if (eternalize) a.Add("--eternalize");
        a.AddRange(new[] { "-l", scriptPath });
        return a;
    }

    public static IReadOnlyList<string> BuildBackgroundArgs(string endpoint, int? pid, string? processName, string scriptPath)
    {
        var a = new List<string> { "-H", endpoint };
        a.AddRange(TargetArgs(pid, processName));
        a.AddRange(new[] { "-q", "-t", "inf", "-l", scriptPath });
        return a;
    }

    public static IReadOnlyList<string> BuildListArgs(string endpoint) => new[] { "-H", endpoint };

    /// <summary>The guest command line that start_server runs (through WMI, outside the SSH session).</summary>
    public static string BuildServerCommandLine(string serverPath, string guestIp, int port, string? token) =>
        $"\"{serverPath}\" -l {guestIp}:{port.ToString(CultureInfo.InvariantCulture)}" +
        (string.IsNullOrEmpty(token) ? "" : " --token " + token);

    /// <summary>Environment for frida.exe and frida-ps.exe: FRIDA_TOKEN when a token is configured.</summary>
    public static IReadOnlyDictionary<string, string>? ToolEnvironment(string? token) =>
        string.IsNullOrEmpty(token) ? null : new Dictionary<string, string> { ["FRIDA_TOKEN"] = token };

    // ===============================================================
    //  ONE-SHOT RUNS
    // ===============================================================

    /// <summary>Evaluate one expression in the target. frida exits after it, which removes any hooks it set.</summary>
    public async Task<FridaResult> EvalAsync(int? pid, string? processName, string expression, int timeoutSeconds, CancellationToken ct)
        => await RunFridaToolAsync("frida.exe", BuildEvalArgs(GuestEndpoint, pid, processName, expression),
            TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 1, 3600)), ct);

    /// <summary>
    /// Run a script for <paramref name="timeoutSeconds"/>. With <paramref name="eternalize"/> the agent stays
    /// loaded after frida.exe exits, so hooks remain until the target process exits.
    /// </summary>
    public async Task<FridaResult> InjectAsync(int? pid, string? processName, string script, int timeoutSeconds,
        bool eternalize, CancellationToken ct)
    {
        timeoutSeconds = Math.Clamp(timeoutSeconds, 1, 3600);
        var scriptPath = Path.Combine(Path.GetTempPath(), $"frida_script_{Guid.NewGuid():N}.js");
        try
        {
            await File.WriteAllTextAsync(scriptPath, script, ct);
            var r = await RunFridaToolAsync("frida.exe",
                BuildInjectArgs(GuestEndpoint, pid, processName, scriptPath, timeoutSeconds, eternalize),
                TimeSpan.FromSeconds(timeoutSeconds + 5), ct);
            return r.Success && eternalize
                ? new FridaResult(true, "Script injected and eternalized (its hooks stay until the target exits).\n" + r.Output)
                : r;
        }
        finally
        {
            try { File.Delete(scriptPath); } catch { }
        }
    }

    public Task<FridaResult> ListProcessesAsync(CancellationToken ct)
        => RunFridaToolAsync("frida-ps.exe", BuildListArgs(GuestEndpoint), TimeSpan.FromSeconds(15), ct);

    private async Task<FridaResult> RunFridaToolAsync(string exeName, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct)
    {
        var path = ToolPaths.FridaTool(_config.Host, exeName);
        if (path == null)
            return new FridaResult(false, NotFound(exeName));

        _logger.LogDebug("Running {Tool} {Args}", path, Redact.Arguments(args));
        ProcessResult r;
        try
        {
            r = await ProcessRunner.RunAsync(path, args, timeout, ct, exeName, ToolEnvironment(_config.Guest.FridaToken));
        }
        catch (TimeoutException ex)
        {
            return new FridaResult(false, ex.Message);
        }

        // frida writes most of its output to stderr. Combine both streams.
        var output = r.Stdout.Trim();
        var error = r.Stderr.Trim();
        var combined = output.Length == 0 ? error : error.Length == 0 ? output : output + "\n" + error;

        if (r.ExitCode == 0)
            return new FridaResult(true, combined.Length == 0 ? "(no output)" : combined);

        // frida in quiet mode (-q) can exit with code 1 after a successful run. Treat exit 1 with output and no
        // error text as success.
        if (r.ExitCode == 1 && combined.Length > 0 && !combined.Contains("Failed to") &&
            !combined.Contains("Error:") && !combined.Contains("unable to"))
            return new FridaResult(true, combined);

        return new FridaResult(false, $"{exeName} exited with code {r.ExitCode}: {(combined.Length == 0 ? "(no output)" : combined)}");
    }

    private string NotFound(string exeName) =>
        string.IsNullOrWhiteSpace(_config.Host.FridaToolsPath)
            ? $"{exeName} was not found on PATH (relative PATH entries are ignored). Install frida-tools " +
              "(pip install frida-tools) and set Host.FridaToolsPath to its Scripts folder."
            : $"{exeName} was not found in Host.FridaToolsPath ({_config.Host.FridaToolsPath}).";

    // ===============================================================
    //  BACKGROUND SESSION (inject_bg / collect_bg / stop_bg)
    // ===============================================================

    /// <summary>
    /// Start a frida.exe -t inf session whose hooks stay until stop_bg. Output is buffered (at most
    /// <see cref="MaxBackgroundChars"/> characters; the oldest text is dropped first) and returned by collect_bg.
    /// The call takes the one background slot under the lock and holds it until it returns, so a second
    /// inject_bg that arrives while frida.exe starts is refused. Without that, both calls would start a
    /// frida.exe, and the first one would keep running with nothing (stop_bg, vm_stop, shutdown) to end it.
    /// </summary>
    public async Task<FridaResult> StartBackgroundAsync(int? pid, string? processName, string script, CancellationToken ct)
    {
        var refusal = TryReserveBackgroundStart();
        if (refusal != null)
            return new FridaResult(false, refusal);
        try
        {
            return await StartReservedBackgroundAsync(pid, processName, script, ct);
        }
        finally
        {
            ReleaseBackgroundStart();
        }
    }

    /// <summary>Take the background slot: null when the caller holds it now, else why it cannot.</summary>
    internal string? TryReserveBackgroundStart()
    {
        lock (_bgLock)
        {
            if (_bgStarting)
                return "Another inject_bg call is still starting a background session. Wait for it to return, " +
                       "then call umd_frida(action='collect_bg') or umd_frida(action='stop_bg').";
            if (_bgProcess != null && !HasExited(_bgProcess))
                return $"A background session is already running on {_bgTarget}. Call umd_frida(action='stop_bg') first.";
            CleanupBackgroundLocked();
            _bgStarting = true;
            return null;
        }
    }

    internal void ReleaseBackgroundStart()
    {
        lock (_bgLock) _bgStarting = false;
    }

    private async Task<FridaResult> StartReservedBackgroundAsync(int? pid, string? processName, string script, CancellationToken ct)
    {
        var path = ToolPaths.FridaTool(_config.Host, "frida.exe");
        if (path == null)
            return new FridaResult(false, NotFound("frida.exe"));

        var scriptPath = Path.Combine(Path.GetTempPath(), $"frida_bg_{Guid.NewGuid():N}.js");
        await File.WriteAllTextAsync(scriptPath, script, ct);

        var args = BuildBackgroundArgs(GuestEndpoint, pid, processName, scriptPath);
        var psi = ProcessRunner.StartInfo(path, args, ToolEnvironment(_config.Guest.FridaToken));
        _logger.LogDebug("Starting background frida session: {Args}", Redact.Arguments(args));

        Process process;
        try
        {
            process = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            try { File.Delete(scriptPath); } catch { }
            return new FridaResult(false, $"frida.exe could not be started: {ex.Message}");
        }
        try { process.StandardInput.Close(); } catch (IOException) { }

        var target = pid.HasValue ? $"PID {pid.Value}" : $"'{processName}'";
        lock (_bgLock)
        {
            _bgProcess = process;
            _bgScriptPath = scriptPath;
            _bgTarget = target;
            _bgOutput.Clear();
            _bgDropped = 0;
        }

        _ = Task.Run(() => PumpAsync(process, process.StandardOutput), CancellationToken.None);
        _ = Task.Run(() => PumpAsync(process, process.StandardError), CancellationToken.None);

        // Wait briefly to catch an immediate failure (bad script, target gone, frida-server unreachable).
        await Task.Delay(1500, ct);

        if (HasExited(process))
        {
            var output = TakeOutput();
            StopBackground();
            return new FridaResult(false, $"The background session ended at once: {output}");
        }

        var early = TakeOutput();
        return new FridaResult(true,
            $"Background session started on {target}. Its hooks stay active until stop_bg. " +
            "Read its output with umd_frida(action='collect_bg')." +
            (early.Length > 0 ? "\n\nFirst output:\n" + early : ""));
    }

    private async Task PumpAsync(Process owner, StreamReader reader)
    {
        var buffer = new char[4096];
        try
        {
            int n;
            while ((n = await reader.ReadAsync(buffer.AsMemory())) > 0)
            {
                lock (_bgLock)
                {
                    if (!ReferenceEquals(_bgProcess, owner)) return;   // a later session replaced this one
                    _bgOutput.Append(buffer, 0, n);
                    var excess = _bgOutput.Length - MaxBackgroundChars;
                    if (excess > 0)
                    {
                        _bgOutput.Remove(0, excess);
                        _bgDropped += excess;
                    }
                }
            }
        }
        catch
        {
            // The process exited or was ended.
        }
    }

    private string TakeOutput()
    {
        lock (_bgLock)
        {
            var text = _bgOutput.ToString().Trim();
            var dropped = _bgDropped;
            _bgOutput.Clear();
            _bgDropped = 0;
            return dropped == 0
                ? text
                : $"[{dropped:N0} earlier characters were dropped: the buffer keeps the last {MaxBackgroundChars:N0}]\n" + text;
        }
    }

    public FridaResult CollectBackground()
    {
        bool running;
        lock (_bgLock) running = _bgProcess != null && !HasExited(_bgProcess);
        var output = TakeOutput();
        if (!running && output.Length == 0)
            return new FridaResult(false, "No background session is running.");
        return new FridaResult(true, (output.Length == 0 ? "(no new output)" : output) +
                                     (running ? "" : "\n[the background session has ended]"));
    }

    public FridaResult StopBackground()
    {
        Process? process;
        lock (_bgLock) process = _bgProcess;
        if (process == null)
            return new FridaResult(false, "No background session to stop.");

        try
        {
            if (!HasExited(process)) process.Kill(entireProcessTree: true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error ending the background frida process");
        }

        var output = TakeOutput();
        lock (_bgLock) CleanupBackgroundLocked();
        return new FridaResult(true, "Background session stopped; its hooks were removed when frida.exe exited." +
                                     (output.Length > 0 ? "\n\nLast output:\n" + output : ""));
    }

    private void CleanupBackgroundLocked()
    {
        try { _bgProcess?.Dispose(); } catch { }
        _bgProcess = null;
        _bgTarget = null;
        if (_bgScriptPath != null)
        {
            try { File.Delete(_bgScriptPath); } catch { }
            _bgScriptPath = null;
        }
    }

    private static bool HasExited(Process p)
    {
        try { return p.HasExited; }
        catch { return true; }
    }

    /// <summary>Stop a background session (vm_stop and shutdown). Repeatable.</summary>
    public void ResetSession()
    {
        bool running;
        lock (_bgLock) running = _bgProcess != null;
        if (running) StopBackground();
    }

    public void Dispose() => ResetSession();
}

public sealed record FridaResult(bool Success, string Output);
