using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.HyperV;

/// <summary>
/// One run of a lab task, as reported by the host worker in &lt;InstallRoot&gt;\&lt;Lab&gt;\state\&lt;Action&gt;.json
/// (schema hvlab-result/1 of hyperv-lpe-lab).
/// </summary>
public sealed record LabTaskResult(
    bool Ok,
    string Message,
    string? VmName,
    string? StateBefore,
    string? StateAfter,
    string? Heartbeat,
    long? UptimeSec,
    IReadOnlyList<string> Ipv4,
    DateTime StartedUtc,
    DateTime FinishedUtc)
{
    public string Describe(string action)
    {
        var parts = new List<string> { $"{action}: {(Ok ? "ok" : "FAILED")}" };
        if (!string.IsNullOrWhiteSpace(Message)) parts.Add(Message.Trim());
        if (StateAfter != null) parts.Add($"VM state {StateAfter}" + (StateBefore != null ? $" (before: {StateBefore})" : ""));
        if (!string.IsNullOrEmpty(Heartbeat)) parts.Add($"heartbeat {Heartbeat}");
        if (Ipv4.Count > 0) parts.Add("IPv4 " + string.Join(", ", Ipv4));
        return string.Join(". ", parts) + ".";
    }
}

/// <summary>
/// Runs the on-demand scheduled tasks of the host automation (hyperv-lpe-lab) through the Task Scheduler
/// COM API, the same way that project's Invoke-HvLabVm.ps1 does, and reads the result file the task's
/// worker writes.
///
/// Contract (defined by hyperv-lpe-lab; see architecture.md, "VM lifecycle"):
///   task       \HyperVLpeLab\&lt;Lab&gt;\&lt;Action&gt;   (Action: Start, Stop, TurnOff, Pause, Resume, Status)
///   result     &lt;InstallRoot&gt;\&lt;Lab&gt;\state\&lt;Action&gt;.json, replaced in one step by the worker
///   log        &lt;InstallRoot&gt;\&lt;Lab&gt;\logs\worker.log
/// The task takes no parameters. This class starts it, waits, and reads the result. It sends nothing else.
/// </summary>
public sealed class LabTaskClient
{
    public const string TaskRootName = "HyperVLpeLab";
    public const string ResultSchema = "hvlab-result/1";
    private const int TaskStateRunning = 4;                       // TASK_STATE_RUNNING
    private const int HrFileNotFound = unchecked((int)0x80070002);
    private const int HrAccessDenied = unchecked((int)0x80070005);

    public static readonly IReadOnlyList<string> Actions = new[] { "Start", "Stop", "TurnOff", "Pause", "Resume", "Status" };

    private readonly ILogger _logger;

    public string Lab { get; }
    public string LabDirectory { get; }
    public string TaskFolder => $@"\{TaskRootName}\{Lab}";

    public LabTaskClient(string lab, string installRoot, ILogger logger)
    {
        Lab = lab;
        LabDirectory = Path.Combine(installRoot, lab);
        _logger = logger;
    }

    public string ResultPath(string action) => Path.Combine(LabDirectory, "state", action + ".json");

    /// <summary>
    /// Start the task and wait up to <paramref name="waitSeconds"/> for its result.
    /// A run that has not finished by then is reported as pending, not as a failure.
    /// </summary>
    public async Task<VmResult> RunAsync(string action, int waitSeconds, CancellationToken ct)
    {
        if (!Actions.Contains(action))
            return VmResult.Failed($"Unknown lab action '{action}'.");

        var taskPath = $@"{TaskFolder}\{action}";
        dynamic folder;
        dynamic task;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service")
                       ?? throw new InvalidOperationException("the Task Scheduler COM class is not registered");
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            folder = service.GetFolder(TaskFolder);
            task = folder.GetTask(action);
        }
        catch (COMException ex) when (ex.HResult == HrFileNotFound)
        {
            return VmResult.Failed($"Task {taskPath} was not found. Run Install-HvLab.ps1 of hyperv-lpe-lab for lab '{Lab}' (elevated, once).");
        }
        catch (COMException ex) when (ex.HResult == HrAccessDenied)
        {
            return VmResult.Failed($"Access to task {taskPath} was denied. Only the operator account named at install may run it.");
        }
        catch (Exception ex)
        {
            return VmResult.Failed($"Cannot open task {taskPath}: {ex.Message}");
        }

        if ((int)task.State == TaskStateRunning)
            return VmResult.Failed($"Task {taskPath} is already running (one run at a time). Try again when it ends.");

        var triggeredUtc = DateTime.UtcNow;
        try
        {
            task.Run(null);
        }
        catch (COMException ex)
        {
            return VmResult.Failed($"Task {taskPath} could not be started (0x{ex.HResult:X8}): {ex.Message}");
        }
        _logger.LogInformation("Started task {Task}", taskPath);

        var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
        LabTaskResult? result = null;
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(500, ct);

            // The task state first, then the result file: the worker writes the result before the task ends,
            // so a task seen as done always has its result visible to the read below.
            bool done;
            DateTime lastRunUtc;
            uint lastResult;
            try
            {
                task = folder.GetTask(action);
                done = (int)task.State != TaskStateRunning;
                lastRunUtc = ((DateTime)task.LastRunTime).ToUniversalTime();
                lastResult = unchecked((uint)(int)task.LastTaskResult);
            }
            catch (COMException ex)
            {
                // The task state cannot be read right now (for example the Task Scheduler service restarted).
                // The result file still decides; keep polling until the deadline.
                _logger.LogDebug(ex, "Task {Task} state not readable", taskPath);
                result = TryReadResult(ResultPath(action), triggeredUtc) ?? result;
                continue;
            }

            result = TryReadResult(ResultPath(action), triggeredUtc) ?? result;
            if (result != null && done)
                break;

            if (done && result == null && lastRunUtc >= triggeredUtc.AddSeconds(-2) &&
                DateTime.UtcNow - triggeredUtc > TimeSpan.FromSeconds(5))
            {
                return VmResult.Failed($"Task {taskPath} ended (result 0x{lastResult:X8}) without writing a result. " +
                                       $"See {Path.Combine(LabDirectory, "logs", "worker.log")}.");
            }
        }

        if (result == null)
            return VmResult.Pending($"Task {taskPath} was started and has not reported a result after {waitSeconds} s. " +
                                   "Call get_system_state(queryHost=true) to follow it.");

        return result.Ok
            ? VmResult.Ok(result.Describe(action), result)
            : VmResult.Failed(result.Describe(action), result);
    }

    private LabTaskResult? TryReadResult(string path, DateTime triggeredUtc)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return ParseResult(File.ReadAllText(path), triggeredUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The worker replaces the file in one step; a read that races it is retried on the next poll.
            _logger.LogDebug(ex, "Result file {Path} not readable yet", path);
            return null;
        }
    }

    /// <summary>
    /// Parse a result file. Returns null unless it is a finished result of a run that started at or after
    /// <paramref name="triggeredUtc"/> (2 s of slack for clock rounding), so an older run is never reported.
    /// </summary>
    public static LabTaskResult? ParseResult(string json, DateTime triggeredUtc)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json.TrimStart((char)0xFEFF)); }
        catch (JsonException) { return null; }

        using (doc)
        {
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object) return null;

            var schema = Str(r, "schema");
            if (schema != null && schema != ResultSchema) return null;

            if (!TryUtc(Str(r, "startedUtc"), out var started) || !TryUtc(Str(r, "finishedUtc"), out var finished))
                return null;
            if (started < triggeredUtc.AddSeconds(-2)) return null;

            var ok = r.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
            var ipv4 = new List<string>();
            if (r.TryGetProperty("ipv4", out var ipEl))
            {
                if (ipEl.ValueKind == JsonValueKind.Array)
                    ipv4.AddRange(ipEl.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!));
                else if (ipEl.ValueKind == JsonValueKind.String)
                    ipv4.Add(ipEl.GetString()!);
            }
            long? uptime = r.TryGetProperty("uptimeSec", out var upEl) && upEl.ValueKind == JsonValueKind.Number &&
                           upEl.TryGetInt64(out var u) ? u : null;

            return new LabTaskResult(ok, Str(r, "message") ?? "", Str(r, "vmName"), Str(r, "stateBefore"),
                Str(r, "stateAfter"), Str(r, "heartbeat"), uptime, ipv4, started, finished);
        }
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool TryUtc(string? s, out DateTime utc)
    {
        utc = default;
        if (string.IsNullOrWhiteSpace(s)) return false;
        if (!DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d)) return false;
        utc = d.ToUniversalTime();
        return true;
    }
}
