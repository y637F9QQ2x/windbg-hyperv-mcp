using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ClrDebug;
using ClrDebug.DbgEng;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.KernelDebug.Interop;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.Security;
using WinDbgMCP.Server.State;

namespace WinDbgMCP.Server.KernelDebug;

/// <summary>
/// Manages the DbgEng kernel debugging session. All DbgEng COM operations are marshaled to the dedicated
/// DbgEngThread; only SetInterrupt and GetInterrupt, which DbgEng allows from any thread, are called from timer
/// threads.
///
/// While the target runs, the DbgEng thread waits for events (WaitForEvent with an INFINITE timeout, as live
/// kernel targets require) and does not interrupt the target. When a tool call queues work, the wait is ended
/// with SetInterrupt(DEBUG_INTERRUPT_EXIT), which returns from WaitForEvent without breaking into the target.
/// Only if that wait has not ended 2 s later does the pump fall back to a break-in (DEBUG_INTERRUPT_ACTIVE).
/// </summary>
public sealed class DbgEngManager : IDisposable
{
    private const int EPending = unchecked((int)0x8000000A);
    private const int WaitInfinite = unchecked((int)0xFFFFFFFF);
    private const int FallbackBreakInMs = 2000;
    private const int RunLogMaxChars = 1_000_000;

    private readonly DbgEngThread _thread;
    private readonly ServerConfig _config;
    private readonly ILogger<DbgEngManager> _logger;
    private readonly OutputCapture _outputCapture = new();
    private readonly DebugEventCallbacks _eventCallbacks = new();

    private volatile DebugClient? _client;            // set and used on the DbgEng thread; read anywhere for IsConnected
    private volatile DebugControl? _interruptControl; // SetInterrupt and GetInterrupt from timer threads
    private bool _disposed;

    // Output written while the target runs (for example by breakpoint commands that end in `gc`) is kept here
    // and returned by kd_wait_for_event. The most recent RunLogMaxChars characters are kept.
    private readonly object _runLogLock = new();
    private readonly StringBuilder _runLog = new();
    private long _runLogDropped;

    // Event pump state. _pumpInWait is 1 while PumpEvents is inside WaitForEvent.
    private int _pumpInWait;
    private int _unrequestedPlainBreaks;   // DbgEng thread only
    private string? _pumpStopEvent;        // DbgEng thread only: .lastevent of a break the pump stopped at by itself
    private const int MaxUnrequestedPlainBreaks = 5;

    public bool IsConnected => _client != null;
    public int PendingEventCount => _eventCallbacks.PendingCount;

    public DbgEngManager(DbgEngThread thread, ServerConfig config, ILogger<DbgEngManager> logger)
    {
        _thread = thread;
        _config = config;
        _logger = logger;

        _thread.PumpEventsAction = PumpEvents;
        _thread.WorkQueued = OnWorkQueued;
        _thread.InterruptRunningWork = () => _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.ACTIVE);
    }

    /// <summary>The DbgEng connection string for the configured transport (values checked by ConfigValidator).</summary>
    public static string BuildConnectionString(KernelDebugConfig kd) =>
        (kd.Transport ?? "").Equals("serial", StringComparison.OrdinalIgnoreCase)
            ? $"com:pipe,port={kd.Serial.PipeName},resets=0,reconnect"
            : $"net:port={kd.Kdnet.Port},key={kd.Kdnet.Key}";

    /// <summary>Maps dbgeng's DEBUG_STATUS (flag bits removed) to this server's status, by name.</summary>
    public static DebugExecutionStatus MapStatus(DEBUG_STATUS raw) =>
        (DEBUG_STATUS)((long)raw & (long)DEBUG_STATUS.MASK) switch
        {
            DEBUG_STATUS.NO_DEBUGGEE => DebugExecutionStatus.NoDebuggee,
            DEBUG_STATUS.BREAK => DebugExecutionStatus.Break,
            DEBUG_STATUS.GO or DEBUG_STATUS.GO_HANDLED or DEBUG_STATUS.GO_NOT_HANDLED => DebugExecutionStatus.Go,
            DEBUG_STATUS.STEP_OVER or DEBUG_STATUS.STEP_INTO or DEBUG_STATUS.STEP_BRANCH => DebugExecutionStatus.Stepping,
            _ => DebugExecutionStatus.Unknown,
        };

    /// <summary>The execution status cached by the event callbacks. No COM call; safe from any thread.</summary>
    public DebugExecutionStatus GetExecutionStatus() =>
        _client == null ? DebugExecutionStatus.NoDebuggee : MapStatus(_eventCallbacks.LastExecutionStatus);

    private void SetPump(bool on)   // DbgEng thread only
    {
        if (on && !_thread.PumpEnabled)
        {
            _unrequestedPlainBreaks = 0;
            _pumpStopEvent = null;
        }
        _thread.PumpEnabled = on;
    }

    // ===============================================================
    //  CONNECTION
    // ===============================================================

    /// <summary>Connect to the kernel debug target over the configured transport (KDNET or serial pipe).</summary>
    public async Task<string> ConnectKernelAsync()
    {
        var timeout = TimeSpan.FromSeconds(_config.Timeouts.KdConnectSeconds);

        return await _thread.ExecuteAsync(() =>
        {
            // First, before any DbgEng side effect: refuse if another server instance holds the KD session.
            AcquireKdOwnership();
            var sessionLive = false;
            try
            {
                // Load dbgeng.dll by full path from Debugging Tools for Windows. SetDllDirectory makes its
                // dependencies (dbghelp.dll, the KDNET transport) resolve from the same folder.
                var debuggerDir = ToolPaths.DebuggersDirectory(_config.Host)
                    ?? throw new InvalidOperationException(
                        "dbgeng.dll from Debugging Tools for Windows was not found in " +
                        string.Join(" or ", ToolPaths.DebuggerCandidates(_config.Host)) +
                        ". Install the debuggers (a Windows SDK feature), or set Host.DebuggersPath.");
                NativeMethods.SetDllDirectory(debuggerDir);
                _logger.LogInformation("Using dbgeng from: {Dir}", debuggerDir);

                var dbgEngPath = Path.Combine(debuggerDir, "dbgeng.dll");
                var hDbgEng = NativeMethods.LoadLibrary(dbgEngPath);
                if (hDbgEng == IntPtr.Zero)
                    throw new InvalidOperationException($"Failed to load {dbgEngPath} (Win32 error {Marshal.GetLastWin32Error()}).");

                var pDebugCreate = NativeMethods.GetProcAddress(hDbgEng, "DebugCreate");
                if (pDebugCreate == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to find DebugCreate in dbgeng.dll");

                var debugCreate = Marshal.GetDelegateForFunctionPointer<Interop.DebugCreateDelegate>(pDebugCreate);
                var hr = debugCreate(DebugClient.IID_IDebugClient, out var pClient);
                if (hr != HRESULT.S_OK)
                    throw new InvalidOperationException($"DebugCreate failed: {hr}");

                var client = new DebugClient(pClient)
                {
                    OutputCallbacks = _outputCapture,
                    EventCallbacks = _eventCallbacks,
                };

                // INITIAL_BREAK: halt at the connection. DISALLOW_SHELL_COMMANDS: the engine itself refuses
                // .shell (it cannot be unset again in this process), in addition to HostCommandGuard.
                var options = DEBUG_ENGOPT.INITIAL_BREAK;
                if (_config.Policy.BlockHostSideEffectCommands) options |= DEBUG_ENGOPT.DISALLOW_SHELL_COMMANDS;
                client.Control.TryAddEngineOptions(options);

                var symbolPath = Environment.ExpandEnvironmentVariables(_config.KernelDebug.SymbolPath);
                client.Symbols.SymbolPath = symbolPath;
                _logger.LogInformation("Symbol path: {Path}", symbolPath);

                var connStr = BuildConnectionString(_config.KernelDebug);
                _logger.LogInformation("Attaching kernel: {ConnStr}", Redact.ConnectionString(connStr));
                var attachHr = client.TryAttachKernel(DEBUG_ATTACH.KERNEL_CONNECTION, connStr);
                if (attachHr != HRESULT.S_OK)
                    throw new InvalidOperationException($"AttachKernel failed: {attachHr}. " + ErrorMessages.KdConnectFailed);

                _client = client;
                _interruptControl = client.Control;
                sessionLive = true;
                _logger.LogInformation("AttachKernel succeeded, waiting for the initial break...");

                // WaitForEvent for live kernel targets must use an INFINITE timeout. A one-shot break-in at
                // KdInitialBreakSeconds is the safety net if the initial break does not arrive.
                var (waitHr, forced) = WaitWithBreakIn(client, _config.Timeouts.KdInitialBreakSeconds * 1000);
                _outputCapture.Clear();   // the connection banner

                if (waitHr == HRESULT.S_OK)
                {
                    // SYMOPT_DEFERRED_LOADS (0x4), SYMOPT_IGNORE_CVREC (0x80), SYMOPT_NO_UNQUALIFIED_LOADS (0x100),
                    // SYMOPT_FAIL_CRITICAL_ERRORS (0x200), SYMOPT_NO_IMAGE_SEARCH (0x20000): no symbol search that
                    // the model did not ask for. Then a deferred .reload, which loads nothing yet.
                    RunInternal(client, ".symopt+0x4; .symopt+0x80; .symopt+0x100; .symopt+0x200; .symopt+0x20000");
                    RunInternal(client, ".reload");

                    var how = forced
                        ? $"The initial break did not arrive within {_config.Timeouts.KdInitialBreakSeconds} s, so the server broke in; the target is halted."
                        : "The target is halted at the initial break.";
                    return $"Connected to the kernel over {TransportLabel()}. {how} " +
                           "Use kd_execute to inspect it, or kd_continue to resume it.";
                }

                client.TryEndSession(DEBUG_END.ACTIVE_TERMINATE);
                _client = null;
                _interruptControl = null;
                throw new InvalidOperationException($"WaitForEvent failed: {waitHr}. " + ErrorMessages.KdConnectFailed);
            }
            catch
            {
                // No live kernel session was left behind (attach never succeeded, or the failed initial wait
                // already ended it): give the ownership back. A possibly-live session keeps it.
                if (!sessionLive || _client == null)
                    ReleaseKdOwnership();
                throw;
            }
        }, timeout);
    }

    private string TransportLabel() =>
        (_config.KernelDebug.Transport ?? "").Equals("serial", StringComparison.OrdinalIgnoreCase) ? "the serial pipe" : "KDNET";

    // One kernel-debug session per logon session: an MCP client can start a server more than once, and all
    // instances would share one KDNET host port and one VM. Taken by kd_connect only (never at startup, so
    // every instance keeps all of its tools), released by kd_disconnect or at process exit (abandoned). A
    // Mutex has thread affinity, so it is acquired and released on the DbgEng thread only.
    private const string KdOwnerMutexName = @"Local\WinDbgMCP.KernelDebugOwner";
    private Mutex? _kdOwner;
    private bool _ownsKd; // DbgEng thread only

    /// <summary>Throws if another instance holds the KD session. Never blocks. DbgEng thread only.</summary>
    private void AcquireKdOwnership()
    {
        if (_ownsKd) return; // Mutex is recursive; never acquire it twice
        try
        {
            _kdOwner ??= new Mutex(false, KdOwnerMutexName);
        }
        catch (Exception ex)
        {
            // Cannot create/open the guard: fail open (behave exactly as before the guard existed).
            _logger.LogWarning(ex, "Kernel-debug ownership mutex unavailable; continuing without the single-instance guard");
            return;
        }

        bool acquired;
        try { acquired = _kdOwner.WaitOne(0); }
        catch (AbandonedMutexException) { acquired = true; } // the previous owner process died: we own it now
        if (!acquired)
            throw new InvalidOperationException(ErrorMessages.KdOwnedByOtherInstance);
        _ownsKd = true;
    }

    /// <summary>Release KD ownership if held. DbgEng thread only.</summary>
    private void ReleaseKdOwnership()
    {
        if (!_ownsKd) return;
        _ownsKd = false;
        try { _kdOwner?.ReleaseMutex(); }
        catch (ApplicationException) { }
    }

    /// <summary>
    /// Disconnect from the kernel debug target. A halted target is resumed first (through the event pump,
    /// whose WaitForEvent dispatches the GO), so the VM keeps running after the detach.
    /// </summary>
    public async Task<string> DisconnectAsync()
    {
        if (_client == null)
            return "Not connected.";

        var resumed = await _thread.ExecuteAsync(() =>
        {
            var client = _client;
            if (client == null || !IsHalted(client)) return false;
            client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
            SetPump(true);
            return true;
        }, TimeSpan.FromSeconds(5));

        if (resumed)
            await Task.Delay(1000);   // the pump enters WaitForEvent at once and dispatches the GO there

        return await _thread.ExecuteAsync(() =>
        {
            SetPump(false);
            _eventCallbacks.ContextSwitchPending = false;
            var client = _client;
            if (client == null) return "Not connected.";

            var halted = IsHalted(client);
            var hr = client.TryEndSession(DEBUG_END.ACTIVE_DETACH);
            _client = null;
            _interruptControl = null;
            ReleaseKdOwnership();
            _logger.LogInformation("Disconnected from the kernel debugger ({Hr}).", hr);

            if (hr != HRESULT.S_OK)
                return $"Disconnected, but EndSession reported {hr}. The target state is unknown; call get_system_state.";
            return halted
                ? "Disconnected. The target was still halted when the debugger detached; call get_system_state to check the guest."
                : "Disconnected. The target was running when the debugger detached.";
        }, TimeSpan.FromSeconds(10));
    }

    /// <summary>
    /// After vm_stop: end a session that is left over (the VM is gone) on the DbgEng thread, release the
    /// ownership mutex and stop pumping. Returns false when the DbgEng thread did not do it in time.
    /// </summary>
    public async Task<bool> ResetConnectionStateAsync()
    {
        try
        {
            await _thread.ExecuteAsync(() =>
            {
                SetPump(false);
                _eventCallbacks.ContextSwitchPending = false;
                var client = _client;
                _client = null;
                _interruptControl = null;
                if (client != null)
                {
                    try { client.TryEndSession(DEBUG_END.ACTIVE_DETACH); }
                    catch (Exception ex) { _logger.LogDebug(ex, "EndSession after vm_stop failed"); }
                }
                ReleaseKdOwnership();
            }, TimeSpan.FromSeconds(5));
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The kernel debug session could not be closed after vm_stop");
            return false;
        }
    }

    // ===============================================================
    //  COMMAND EXECUTION
    // ===============================================================

    /// <summary>
    /// Execute a WinDbg command (target halted) and capture its output. Two engine-level backstops cover what
    /// the text check of kd_execute cannot see: DEBUG_ENGOPT_DISABLE_EXECUTION_COMMANDS is set while the
    /// command runs, and the execution status is read afterwards; a command that still resumed the target
    /// turns the event pump on and says so.
    /// </summary>
    public async Task<string> ExecuteCommandAsync(string command, int timeoutSeconds)
    {
        return await _thread.ExecuteAsync(() =>
        {
            var client = _client ?? throw new InvalidOperationException("Not connected.");
            if (!IsHalted(client))
                return "The target is running, so kd_execute cannot run a command now. Call kd_break first.";

            client.Control.TryAddEngineOptions(DEBUG_ENGOPT.DISABLE_EXECUTION_COMMANDS);
            HRESULT hr;
            string output;
            try
            {
                _outputCapture.Clear();
                hr = client.Control.TryExecute(DEBUG_OUTCTL.THIS_CLIENT, command, DEBUG_EXECUTE.DEFAULT);
                output = _outputCapture.GetAndClear();
            }
            finally
            {
                client.Control.TryRemoveEngineOptions(DEBUG_ENGOPT.DISABLE_EXECUTION_COMMANDS);
            }

            var interrupted = _thread.CurrentWorkTimedOut;
            client.Control.TryGetInterrupt();   // clear the interrupt a timeout registered, so the next command runs

            var text = hr == HRESULT.S_OK || hr == HRESULT.S_FALSE
                ? output
                : $"Command failed (0x{(int)hr:X8}): {output}";
            if (interrupted)
                text = text.TrimEnd() + $"\n[windbg-hyperv-mcp] The command did not finish within {timeoutSeconds} s and was interrupted; the output above is partial.";

            if (!IsHalted(client))
            {
                SetPump(true);
                return text.TrimEnd() + "\n[windbg-hyperv-mcp] The command resumed the target, which is running now. " +
                       "Call kd_wait_for_event to wait for a breakpoint, or kd_break to halt it.";
            }

            if (IsInvasiveContextSwitchRequest(command, output))
            {
                _eventCallbacks.ContextSwitchPending = true;
                _contextSwitchTarget = ResolveContextSwitchTarget(command);
                text = text.TrimEnd() +
                       "\n[windbg-hyperv-mcp] Invasive context switch pending. Call kd_continue: it runs the " +
                       $"target until the switch break (up to {ContextSwitchWaitSeconds} s) and returns " +
                       "with the target halted in the new process context.";
            }

            return string.IsNullOrWhiteSpace(text) ? "(no output)" : text;
        }, TimeSpan.FromSeconds(timeoutSeconds));
    }

    /// <summary>Run an internal command and discard its output. DbgEng thread only.</summary>
    private void RunInternal(DebugClient client, string command)
    {
        _outputCapture.Clear();
        client.Control.TryExecute(DEBUG_OUTCTL.THIS_CLIENT, command, DEBUG_EXECUTE.DEFAULT);
        _outputCapture.Clear();
    }

    /// <summary>Run an internal command and return its output. DbgEng thread only.</summary>
    private string Capture(DebugClient client, string command)
    {
        _outputCapture.Clear();
        client.Control.TryExecute(DEBUG_OUTCTL.THIS_CLIENT, command, DEBUG_EXECUTE.DEFAULT);
        return _outputCapture.GetAndClear().Trim();
    }

    // ===============================================================
    //  INVASIVE CONTEXT SWITCH (.process /i)
    // ===============================================================

    // `.process /i` only takes effect after the target runs and breaks back in (a first-chance 0x80000003 at
    // nt!RtlpBreakWithStatusInstruction, "after several seconds"). So kd_continue handles a pending switch
    // itself: pump off, one GO, one wait with only a long safety interrupt, and it leaves the target halted.
    private const int ContextSwitchWaitSeconds = 30;

    private static readonly Regex InvasiveProcessCmd = new(
        @"(?:^|;)\s*\.process\b[^;]*?\s/i\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static bool IsInvasiveContextSwitchRequest(string command, string? output)
    {
        var text = Regex.Replace(output ?? "", @"\s+", " ");
        // dbgeng's own reply: "You need to continue execution (press 'g' <enter>) for the context
        // to be switched. When the debugger breaks in again, you will be in the new process context."
        if (text.Contains("to be switched", StringComparison.OrdinalIgnoreCase))
            return true;
        return InvasiveProcessCmd.IsMatch(command) &&
               !text.Contains("error", StringComparison.OrdinalIgnoreCase);
    }

    // A stale interrupt (a break-in already queued at the target) can be delivered right after the GO as a
    // first-chance 0x80000003 in whatever was running (System/idle), before the real switch break. kd_continue
    // must not stop on it, so it compares the broken-in process with the EPROCESS that `.process /i` asked for.
    // 0 = unknown.
    private long _contextSwitchTarget;
    private const int MaxStaleSwitchBreaks = 5;

    private static readonly Regex ProcessCmdArgs = new(
        @"(?:^|;)\s*\.process\b(?<args>[^;]*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// The EPROCESS address named by the `.process /i` in <paramref name="command"/>, or 0 if it cannot be
    /// evaluated (then kd_continue stops at the first break). DbgEng thread only.
    /// </summary>
    private long ResolveContextSwitchTarget(string command)
    {
        long target = 0;
        try
        {
            foreach (Match m in ProcessCmdArgs.Matches(command))
            {
                var args = m.Groups["args"].Value;
                if (!Regex.IsMatch(args, @"(?:^|\s)[/-]i\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    continue;
                var expr = string.Join(" ", args
                    .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                    .Where(t => !t.StartsWith('/') && !t.StartsWith('-')));
                if (expr.Length == 0) continue;

                _outputCapture.Clear();
                var hr = _client!.Control.TryEvaluate(expr, DEBUG_VALUE_TYPE.INT64, out var result);
                _outputCapture.Clear();
                target = hr == HRESULT.S_OK && result.RemainderIndex >= expr.Length ? result.Value.I64 : 0;
            }
        }
        catch
        {
            target = 0;
        }
        return target;
    }

    private static bool SameKernelAddress(long a, long b) =>
        a == b || (a & 0x0000FFFFFFFFFFFF) == (b & 0x0000FFFFFFFFFFFF);

    /// <summary>
    /// true / false = the halted target's implicit or current process is / is not <paramref name="expected"/>;
    /// null = neither could be read (treated like a match, so a real switch break is never skipped).
    /// </summary>
    private static bool? BreakIsInProcess(DebugClient client, long expected)
    {
        try
        {
            var so = client.SystemObjects;
            var known = false;
            if (so.TryGetImplicitProcessDataOffset(out var implicitProc) == HRESULT.S_OK)
            {
                known = true;
                if (SameKernelAddress(implicitProc, expected)) return true;
            }
            if (so.TryGetCurrentProcessDataOffset(out var currentProc) == HRESULT.S_OK)
            {
                known = true;
                if (SameKernelAddress(currentProc, expected)) return true;
            }
            return known ? false : null;
        }
        catch
        {
            return null;
        }
    }

    private const long DBG_STATUS_CONTROL_C = 1; // DbgBreakPointWithStatus status of a debugger break-in

    /// <summary>
    /// true only with positive proof that the halted break is a plain debugger break-in: no bugcheck recorded
    /// (ReadBugCheckData reads code 0), no bugcheck text in <paramref name="lastEvent"/>, and the target sits at
    /// the DbgBreakPointWithStatus int 3 with status DBG_STATUS_CONTROL_C in rcx (a bugcheck breaks there with
    /// BUGCHECK_FIRST/SECOND instead; a hard-coded int 3 or an assertion is somewhere else). Reads @rip and @rcx,
    /// so it is x64 only. Anything unreadable = false. DbgEng thread only.
    /// </summary>
    private bool IsPlainBreakIn(DebugClient client, string lastEvent)
    {
        try
        {
            if (lastEvent.Contains("bugcheck", StringComparison.OrdinalIgnoreCase) ||
                lastEvent.Contains("bug check", StringComparison.OrdinalIgnoreCase) ||
                lastEvent.Contains("fatal system error", StringComparison.OrdinalIgnoreCase))
                return false;

            if (client.Control.TryReadBugCheckData(out var bugCheck) != HRESULT.S_OK || bugCheck.Code != 0)
                return false;

            long? Eval(string expr)
            {
                _outputCapture.Clear();
                var hr = client.Control.TryEvaluate(expr, DEBUG_VALUE_TYPE.INT64, out var r);
                _outputCapture.Clear();
                return hr == HRESULT.S_OK && r.RemainderIndex >= expr.Length ? r.Value.I64 : null;
            }

            var rip = Eval("@rip");
            var rcx = Eval("@rcx");
            if (rip == null || rcx == null || (rcx.Value & 0xFFFFFFFF) != DBG_STATUS_CONTROL_C)
                return false;

            foreach (var sym in new[] { "nt!RtlpBreakWithStatusInstruction", "nt!DbgBreakPointWithStatus" })
            {
                var addr = Eval(sym);
                if (addr != null && addr.Value != 0 && SameKernelAddress(addr.Value, rip.Value))
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>kd_continue while a `.process /i` switch is pending. DbgEng thread only.</summary>
    private string ContinueForContextSwitch()
    {
        var client = _client!;
        SetPump(false);
        var expected = _contextSwitchTarget;
        var deadline = DateTime.UtcNow.AddSeconds(ContextSwitchWaitSeconds);
        var staleBreaks = new List<string>();
        bool? inRequestedProcess = null;
        var notPlainBreakIn = false;
        var realEvent = false;
        var safetyInterruptFired = false;
        HRESULT waitHr;
        try
        {
            while (true)
            {
                // Every wait is armed with the safety break-in at the SAME overall deadline, so re-running past
                // a stale break never extends the total wait beyond ContextSwitchWaitSeconds.
                var remainingMs = (int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds);
                inRequestedProcess = null;
                _eventCallbacks.ClearRealEventFlag();
                _eventCallbacks.ClearLastSwitchBreak();
                client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
                (waitHr, safetyInterruptFired) = WaitWithBreakIn(client, remainingMs);
                StashRunOutput();
                realEvent = _eventCallbacks.RealEventSinceClear;

                // Stop on anything but a bare break outside the requested process: wait failure, no halt, the
                // safety break-in, an unknown target, or a real breakpoint/exception/system error.
                if (waitHr != HRESULT.S_OK || !IsHalted(client) || safetyInterruptFired || expected == 0 || realEvent)
                    break;
                inRequestedProcess = BreakIsInProcess(client, expected);
                if (inRequestedProcess != false)
                    break;

                var staleEvent = Regex.Replace(Capture(client, ".lastevent"), @"\s+", " ");

                // Run on only with positive proof that this is a plain debugger break-in; a bugcheck or a
                // hard-coded int 3 stops here. Checked on EVERY out-of-process break, before the give-up
                // decision, so a bugcheck arriving as the last break still gets the inspect warning.
                if (!IsPlainBreakIn(client, staleEvent))
                {
                    notPlainBreakIn = true;
                    break;
                }

                // Give up (stale-break cap, or under 1 s left, re-checked after IsPlainBreakIn so a re-GO never
                // runs with a near-zero safety timer); the target stays halted at this break.
                if (staleBreaks.Count >= MaxStaleSwitchBreaks || deadline - DateTime.UtcNow < TimeSpan.FromSeconds(1))
                    break;

                // A stale break (not the switch): note it, drop its queued BreakIn entry, run on.
                _eventCallbacks.DiscardLastSwitchBreak();
                staleBreaks.Add(staleEvent);
            }
        }
        catch
        {
            // An exception after a GO must not leave a RUNNING target with the pump off. Re-enable it only on
            // positive proof the target is running; a halted or unreadable target keeps the pump off.
            try
            {
                if (client.Control.ExecutionStatus != DEBUG_STATUS.BREAK)
                    SetPump(true);
            }
            catch { }
            throw;
        }
        finally
        {
            // Cleared on every exit, so the next kd_continue never wrongly takes the context-switch path.
            _eventCallbacks.ContextSwitchPending = false;
        }

        if (waitHr != HRESULT.S_OK || !IsHalted(client))
        {
            SetPump(true);
            return "The wait for the .process /i context switch ended without a break " +
                   (waitHr != HRESULT.S_OK ? $"(WaitForEvent 0x{(int)waitHr:X8}) " : "") +
                   "and the target is running; event pumping is on. Call kd_break, then check '!process -1 0'." +
                   DrainRunLog();
        }

        var lastEvent = Capture(client, ".lastevent");
        var current = Capture(client, "!process -1 0");

        var note = realEvent
            ? "WARNING: a breakpoint, exception or system error broke in before the .process /i switch " +
              "completed, so the switch may not have completed. The target is halted at that event " +
              "('.lastevent' above); inspect it ('k', '.bugcheck') before doing anything else. If the switch " +
              "did not complete, run '.process /i <EPROCESS>' again and kd_continue."
            : safetyInterruptFired
            ? $"WARNING: no switch break arrived within {ContextSwitchWaitSeconds} s; this halt was forced by " +
              "the safety break-in, so the switch may not have completed. Check the process above; to retry, " +
              "run '.process /i <EPROCESS>' again and kd_continue."
            : notPlainBreakIn
                ? $"WARNING: this break is not in the requested process 0x{expected:X16} and could not be " +
                  "confirmed as a plain debugger break-in (it may be a bugcheck, a hard-coded breakpoint or an " +
                  "exception), so the target was left halted here and the switch may not have completed. Inspect " +
                  "it ('.lastevent', '.bugcheck', 'k') before doing anything else."
            : inRequestedProcess == false
                ? $"WARNING: this break is not in the requested process 0x{expected:X16} (gave up after " +
                  $"{staleBreaks.Count} stale break(s)), so the switch may not have completed. Check the process " +
                  "above; to retry, run '.process /i <EPROCESS>' again and kd_continue."
                : "Set breakpoints for this process now, then kd_continue to run.";

        var staleNote = staleBreaks.Count == 0
            ? ""
            : $"\n[windbg-hyperv-mcp] Ran on past {staleBreaks.Count} stale break(s) outside the requested process " +
              "(a leftover break-in, not the switch):\n  " + string.Join("\n  ", staleBreaks);

        var headline = realEvent
            ? "The target ran for the pending .process /i context switch, but a breakpoint, exception or " +
              "system error broke in first. "
            : "The target ran for the pending .process /i context switch and broke back in. ";
        return headline + "The target is halted.\n" +
               $"{lastEvent}\nCurrent process (!process -1 0):\n{current}\n{note}{staleNote}" + DrainRunLog();
    }

    // ===============================================================
    //  EXECUTION CONTROL
    // ===============================================================

    /// <summary>
    /// WaitForEvent(INFINITE) with a break-in (DEBUG_INTERRUPT_ACTIVE) after <paramref name="breakInAfterMs"/>.
    /// If the target does not answer the break-in within 2 s either (for example the VM is gone), the wait is
    /// ended with DEBUG_INTERRUPT_EXIT, so the DbgEng thread is never left waiting forever. Returns the wait
    /// result and whether the break-in fired. DbgEng thread only.
    /// </summary>
    private (HRESULT Hr, bool BreakInFired) WaitWithBreakIn(DebugClient client, int breakInAfterMs)
    {
        var fires = 0;
        var ended = 0;
        HRESULT hr;
        using (new Timer(_ =>
        {
            if (Volatile.Read(ref ended) != 0) return;
            switch (Interlocked.Increment(ref fires))
            {
                case 1: _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.ACTIVE); break;
                case 2: _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.EXIT); break;
            }
        }, null, Math.Max(0, breakInAfterMs), FallbackBreakInMs))
        {
            // An E_PENDING that this timer did not ask for (a stray EXIT from an earlier wait) is waited out.
            var spurious = 0;
            do
            {
                hr = client.Control.TryWaitForEvent(DEBUG_WAIT.DEFAULT, WaitInfinite);
            }
            while ((int)hr == EPending && Volatile.Read(ref fires) < 2 && ++spurious <= 3);
            Volatile.Write(ref ended, 1);
        }
        client.Control.TryGetInterrupt();   // clear an interrupt that is still registered, so the next command runs
        return (hr, Volatile.Read(ref fires) != 0);
    }

    /// <summary>Break into a running target.</summary>
    public async Task<string> BreakAsync()
    {
        var timeout = TimeSpan.FromSeconds(_config.Timeouts.KdBreakSeconds + 5);

        return await _thread.ExecuteAsync(() =>
        {
            var client = _client ?? throw new InvalidOperationException("Not connected.");
            SetPump(false);
            if (IsHalted(client))
                return "The target is already halted.\n" + Capture(client, ".lastevent");

            client.Control.TrySetInterrupt(DEBUG_INTERRUPT.ACTIVE);
            var (waitHr, _) = WaitWithBreakIn(client, _config.Timeouts.KdBreakSeconds * 1000);
            _outputCapture.Clear();   // the break-in banner

            if (waitHr == HRESULT.S_OK && IsHalted(client))
                return "The target is halted.\n" + Capture(client, ".lastevent") +
                       "\nUse kd_execute to inspect it (for example 'k' for the stack, 'r' for registers).";

            if (!IsHalted(client)) SetPump(true);
            return $"The break-in got no answer within {_config.Timeouts.KdBreakSeconds} s (WaitForEvent 0x{(int)waitHr:X8}). " +
                   "The target may be in a state where it cannot break; call get_system_state.";
        }, timeout);
    }

    /// <summary>Resume execution (go). Returns at once.</summary>
    public async Task<string> ContinueAsync()
    {
        var timeout = _eventCallbacks.ContextSwitchPending
            ? TimeSpan.FromSeconds(ContextSwitchWaitSeconds + 15)
            : TimeSpan.FromSeconds(5);

        return await _thread.ExecuteAsync(() =>
        {
            var client = _client ?? throw new InvalidOperationException("Not connected.");
            _eventCallbacks.ClearBreakingEventFlag();

            if (_eventCallbacks.ContextSwitchPending)
                return ContinueForContextSwitch();

            client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
            SetPump(true);
            return "The target is running. Guest tools work again once get_system_state shows Guest SSH reachable. " +
                   "To wait for a breakpoint, call kd_wait_for_event; to halt the target, call kd_break.";
        }, timeout);
    }

    /// <summary>Step one instruction (into or over).</summary>
    public async Task<string> StepAsync(bool into)
    {
        var timeout = TimeSpan.FromSeconds(_config.Timeouts.KdStepSeconds + 5);
        var mode = into ? "into" : "over";

        return await _thread.ExecuteAsync(() =>
        {
            var client = _client ?? throw new InvalidOperationException("Not connected.");

            // A step is not the `g` that completes a pending `.process /i`; fall back to normal handling.
            _eventCallbacks.ContextSwitchPending = false;
            client.Control.TrySetExecutionStatus(into ? DEBUG_STATUS.STEP_INTO : DEBUG_STATUS.STEP_OVER);

            var (waitHr, forced) = WaitWithBreakIn(client, _config.Timeouts.KdStepSeconds * 1000);
            StashRunOutput();

            if (waitHr == HRESULT.S_OK && IsHalted(client))
            {
                var where = Capture(client, "r rip") + "\n" + Capture(client, "u . L1");
                return forced
                    ? $"The step ({mode}) did not complete within {_config.Timeouts.KdStepSeconds} s, so the server broke in. " +
                      $"The target is halted at:\n{where}"
                    : $"Stepped {mode}.\n{where}";
            }

            if (!IsHalted(client)) SetPump(true);
            return $"The step ({mode}) did not complete and the break-in got no answer (WaitForEvent 0x{(int)waitHr:X8}). " +
                   "The target may be running; call get_system_state, then kd_break or kd_wait_for_event.";
        }, timeout);
    }

    // kd_wait_for_event runs on past at most this many stray break-ins (a plain 0x80000003 debugger break-in
    // that nobody asked for) in one call, always inside its deadline.
    private const int MaxStaleWaitBreaks = 5;

    /// <summary>
    /// Wait for a debug event (breakpoint hit, exception, etc.). <paramref name="deadlineUtc"/> is the caller's
    /// end-to-end deadline. At the deadline the wait is ended with DEBUG_INTERRUPT_EXIT, which does not break
    /// into the target, so a wait without an event leaves the target running untouched. If that wait has not
    /// ended 2 s later, a break-in is the fallback, and the target is resumed after it.
    /// </summary>
    public async Task<string> WaitForEventAsync(int timeoutSeconds, DateTime deadlineUtc)
    {
        var now = DateTime.UtcNow;
        var deadline = deadlineUtc - now < TimeSpan.FromSeconds(1) ? now.AddSeconds(1) : deadlineUtc;
        var timeout = deadline - now + TimeSpan.FromSeconds(5) + TimeSpan.FromMilliseconds(FallbackBreakInMs);

        return await _thread.ExecuteAsync(() =>
        {
            var client = _client ?? throw new InvalidOperationException("Not connected.");

            // The target is already halted and not being pumped (kd_break / kd_step / initial break, or the pump
            // already stopped at an event after kd_continue). Report it and do NOT call WaitForEvent: that would
            // run the target on past the event the pump already caught.
            if (!_thread.PumpEnabled && IsHalted(client))
            {
                var caught = _eventCallbacks.HasBreakingEvent || _eventCallbacks.RealEventSinceClear || _pumpStopEvent != null;
                var haltedEvent = Capture(client, ".lastevent");
                if (caught)
                {
                    // Reported now; a later kd_wait_for_event without kd_continue must not report it again.
                    _eventCallbacks.ClearBreakingEventFlag();
                    _eventCallbacks.ClearRealEventFlag();
                    _pumpStopEvent = null;
                    return "Debug event received (it broke in before this call, while the target ran). " +
                           $"The target is halted.\n{haltedEvent}{QueuedEventSummary()}{DrainRunLog()}";
                }
                return "The target is already halted (no new debug event since it halted); kd_wait_for_event did " +
                       "not resume it. Inspect it with kd_execute, or call kd_continue to run it and then " +
                       $"kd_wait_for_event.\n{haltedEvent}{QueuedEventSummary()}{DrainRunLog()}";
            }

            SetPump(false);
            // Only events that break in during THIS wait count (a resume clears these flags anyway).
            _eventCallbacks.ClearBreakingEventFlag();
            _eventCallbacks.ClearRealEventFlag();
            var absorbed = 0;

            while (true)
            {
                var remainingMs = (int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds);
                var exitFired = 0;
                var breakFired = 0;
                var ended = 0;
                HRESULT waitHr;
                using (new Timer(_ =>
                {
                    if (Volatile.Read(ref ended) != 0) return;
                    if (Interlocked.Exchange(ref exitFired, 1) == 0)
                        _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.EXIT);
                    else if (Interlocked.Exchange(ref breakFired, 1) == 0)
                        _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.ACTIVE);   // EXIT did not end the wait
                }, null, remainingMs, FallbackBreakInMs))
                {
                    // An E_PENDING before the deadline is a stray EXIT from an earlier wait: wait again.
                    var spurious = 0;
                    do
                    {
                        waitHr = client.Control.TryWaitForEvent(DEBUG_WAIT.DEFAULT, WaitInfinite);
                    }
                    while ((int)waitHr == EPending && Volatile.Read(ref exitFired) == 0 && ++spurious <= 3);
                    Volatile.Write(ref ended, 1);
                }
                client.Control.TryGetInterrupt();
                StashRunOutput();
                var deadlineReached = Volatile.Read(ref exitFired) != 0;

                if ((int)waitHr == EPending || waitHr != HRESULT.S_OK || !IsHalted(client))
                {
                    // EXIT ended the wait without a break (or the target is running for another reason).
                    SetPump(true);
                    return NoEventText(deadlineReached
                        ? $"No debug event within {timeoutSeconds} s."
                        : $"The wait ended without a debug event (WaitForEvent 0x{(int)waitHr:X8}).", absorbed);
                }

                var realEvent = _eventCallbacks.RealEventSinceClear || _eventCallbacks.HasBreakingEvent;
                var lastEvent = Capture(client, ".lastevent");

                if (realEvent)
                {
                    _eventCallbacks.ClearBreakingEventFlag();
                    _eventCallbacks.ClearRealEventFlag();
                    return EventReceivedText(lastEvent, absorbed);
                }

                // A bare break with no breakpoint/exception/system error callback. Run on only with positive proof
                // it is a plain debugger break-in (no bugcheck, DbgBreakPointWithStatus(DBG_STATUS_CONTROL_C));
                // anything else (a hard-coded int 3, an assertion, a bugcheck, unreadable state) stays halted and
                // is reported as an event.
                if (!IsPlainBreakIn(client, lastEvent))
                {
                    var note = Volatile.Read(ref breakFired) != 0
                        ? "\n[windbg-hyperv-mcp] This break arrived as the wait's fallback break-in fired at the deadline " +
                          "and could not be proven to be a plain debugger break-in, so the target was left halted here. " +
                          "Inspect it ('.lastevent', 'k', '.bugcheck') before continuing."
                        : "";
                    return EventReceivedText(lastEvent, absorbed) + note;
                }

                // Our own fallback break-in at the deadline, the stray-break cap, or under 1 s left (checked after
                // IsPlainBreakIn so a re-GO never runs with a near-zero timer): resume the target and report a
                // timeout, so a timeout leaves the target running.
                var outOfTime = deadlineReached || deadline - DateTime.UtcNow < TimeSpan.FromSeconds(1);
                if (outOfTime || absorbed >= MaxStaleWaitBreaks)
                {
                    client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
                    SetPump(true);
                    return outOfTime
                        ? NoEventText($"No debug event within {timeoutSeconds} s.", absorbed)
                        : NoEventText($"No debug event (stopped waiting early after {absorbed} stray debugger break-ins).", absorbed);
                }

                // A stray break-in (not an event and not our deadline): run on and keep waiting.
                absorbed++;
                _eventCallbacks.ClearBreakingEventFlag();
                _eventCallbacks.ClearRealEventFlag();
                client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
            }
        }, timeout);
    }

    /// <summary>True only if the target's execution status reads BREAK. Unreadable = false. DbgEng thread only.</summary>
    private static bool IsHalted(DebugClient client)
    {
        try { return client.Control.ExecutionStatus == DEBUG_STATUS.BREAK; }
        catch { return false; }
    }

    /// <summary>Drain queued events into the kd_wait_for_event summary text. DbgEng thread only.</summary>
    private string QueuedEventSummary()
    {
        var events = _eventCallbacks.DrainEvents();
        return events.Count > 0
            ? "\nQueued events:\n" + string.Join("\n", events.Select(e => $"  {e}"))
            : "";
    }

    private static string StrayBreakNote(int absorbed) =>
        absorbed == 0
            ? ""
            : $"\n[windbg-hyperv-mcp] Ran on past {absorbed} stray debugger break-in(s) (a leftover break-in, not an event).";

    private string EventReceivedText(string lastEvent, int absorbed) =>
        $"Debug event received. The target is halted.\n{lastEvent}{QueuedEventSummary()}" +
        StrayBreakNote(absorbed) + DrainRunLog();

    private string NoEventText(string headline, int absorbed) =>
        headline + " The target is still running. Call kd_wait_for_event again to keep waiting, or kd_break to " +
        "halt it. Guest tools work while it runs." + StrayBreakNote(absorbed) + DrainRunLog();

    // ===============================================================
    //  RUN LOG
    // ===============================================================

    /// <summary>Move output printed during a wait into the run log (keeps the last RunLogMaxChars characters).</summary>
    private void StashRunOutput()
    {
        var s = _outputCapture.GetAndClear();
        if (string.IsNullOrWhiteSpace(s)) return;
        lock (_runLogLock)
        {
            _runLog.Append(s);
            var excess = _runLog.Length - RunLogMaxChars;
            if (excess > 0)
            {
                _runLog.Remove(0, excess);
                _runLogDropped += excess;
            }
        }
    }

    private string DrainRunLog()
    {
        lock (_runLogLock)
        {
            if (_runLog.Length == 0) return "";
            var s = _runLog.ToString().TrimEnd();
            var dropped = _runLogDropped;
            _runLog.Clear();
            _runLogDropped = 0;
            return "\nOutput printed while the target ran (breakpoint commands):\n" +
                   (dropped > 0 ? $"[{dropped:N0} earlier characters were dropped: the log keeps the last {RunLogMaxChars:N0}]\n" : "") + s;
        }
    }

    // ===============================================================
    //  BUGCHECK DETECTION
    // ===============================================================

    /// <summary>Whether the current break is a bugcheck. Call while the target is halted.</summary>
    public async Task<(bool IsBugcheck, string? BugcheckCode)> DetectBugcheckAsync()
    {
        return await _thread.ExecuteAsync(() =>
        {
            var client = _client;
            if (client == null || !IsHalted(client))
                return (false, (string?)null);

            var output = Capture(client, ".lastevent");
            if (output.Contains("bugcheck", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Bug Check", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(output, @"[Bb]ug\s*[Cc]heck\s+([\dA-Fa-f]+)");
                var code = match.Success ? $"0x{match.Groups[1].Value}" : null;
                return (true, code);
            }

            return (false, (string?)null);
        }, TimeSpan.FromSeconds(10));
    }

    // ===============================================================
    //  EVENT PUMP (called by DbgEngThread while no work is queued and the target runs)
    // ===============================================================

    /// <summary>A tool call queued DbgEng work: end the pump's wait without breaking into the target.</summary>
    private void OnWorkQueued()
    {
        if (Volatile.Read(ref _pumpInWait) == 1)
            _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.EXIT);
    }

    private void PumpEvents()
    {
        var client = _client;
        if (client == null)
        {
            SetPump(false);
            return;
        }

        // Publish "in the wait" before the last look at the queue: work queued after this point finds the flag
        // set and ends the wait (OnWorkQueued), work queued before it is seen here.
        Interlocked.Exchange(ref _pumpInWait, 1);
        if (_thread.HasPendingWork)
        {
            Interlocked.Exchange(ref _pumpInWait, 0);
            return;
        }

        // The watchdog acts only while a tool call waits for this thread: it repeats the EXIT (in case the first
        // one arrived before WaitForEvent started) and, 2 s after the first EXIT, falls back to a break-in.
        long firstExitAt = 0;
        var breakInSent = 0;
        HRESULT hr;
        using (new Timer(_ =>
        {
            if (Volatile.Read(ref _pumpInWait) == 0 || !_thread.HasPendingWork) return;
            var nowMs = Environment.TickCount64;
            if (Interlocked.CompareExchange(ref firstExitAt, nowMs, 0) == 0 || nowMs - Interlocked.Read(ref firstExitAt) < FallbackBreakInMs)
                _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.EXIT);
            else if (Interlocked.Exchange(ref breakInSent, 1) == 0)
                _interruptControl?.TrySetInterrupt(DEBUG_INTERRUPT.ACTIVE);
        }, null, 500, 500))
        {
            try
            {
                hr = client.Control.TryWaitForEvent(DEBUG_WAIT.DEFAULT, WaitInfinite);
            }
            finally
            {
                Interlocked.Exchange(ref _pumpInWait, 0);
            }
        }
        client.Control.TryGetInterrupt();   // clear an EXIT or break-in request that arrived after the wait ended
        StashRunOutput();

        if ((int)hr == EPending)
            return;   // EXIT ended the wait; the target keeps running and the queued work runs next

        if (hr != HRESULT.S_OK)
        {
            _logger.LogWarning("WaitForEvent failed in the event pump ({Hr}); event pumping stopped.", hr);
            SetPump(false);
            return;
        }

        if (!IsHalted(client))
            return;   // still running (for example a breakpoint command ended in gc)

        if (_eventCallbacks.HasBreakingEvent)
        {
            // A breakpoint, second-chance exception or system error: stay halted until kd_wait_for_event reports it.
            SetPump(false);
            return;
        }

        // A break without such a callback: our own fallback break-in, a stray one, a hard-coded int 3 or an
        // assertion (first chance), or a bugcheck. Resume only a proven plain debugger break-in, and at most
        // MaxUnrequestedPlainBreaks of them that nobody asked for.
        var lastEvent = Capture(client, ".lastevent");
        if (IsPlainBreakIn(client, lastEvent) &&
            (Volatile.Read(ref breakInSent) != 0 || ++_unrequestedPlainBreaks <= MaxUnrequestedPlainBreaks))
        {
            client.Control.TrySetExecutionStatus(DEBUG_STATUS.GO);
            return;
        }

        // Stay halted; kd_wait_for_event reports this break as an event.
        _pumpStopEvent = lastEvent;
        SetPump(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_client == null) return;

        // End the session on the DbgEng thread (DbgEng thread affinity), with a short timeout.
        try
        {
            _thread.ExecuteAsync(() =>
            {
                SetPump(false);
                var client = _client;
                _client = null;
                _interruptControl = null;
                client?.TryEndSession(DEBUG_END.ACTIVE_DETACH);
                ReleaseKdOwnership();
            }, TimeSpan.FromSeconds(3)).Wait(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Ending the kernel debug session at shutdown failed");
        }
    }
}
