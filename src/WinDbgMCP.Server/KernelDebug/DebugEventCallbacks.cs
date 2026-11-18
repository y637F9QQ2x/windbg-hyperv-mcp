using System.Collections.Concurrent;
using ClrDebug;
using ClrDebug.DbgEng;
using WinDbgMCP.Server.KernelDebug.Models;

namespace WinDbgMCP.Server.KernelDebug;

/// <summary>
/// Handles debug events from the kernel debug target. Events are queued (at most <see cref="MaxQueuedEvents"/>,
/// oldest dropped first) for the kd_wait_for_event summary.
/// </summary>
public sealed class DebugEventCallbacks : DebugBaseEventCallbacks
{
    public const int MaxQueuedEvents = 1000;

    private const uint STATUS_BREAKPOINT = 0x80000003;
    private const uint STATUS_ASSERTION_FAILURE = 0xC0000420;

    private readonly ConcurrentQueue<DebugEvent> _eventQueue = new();
    private volatile DEBUG_STATUS _lastExecutionStatus = DEBUG_STATUS.NO_DEBUGGEE;
    private volatile bool _hasBreakingEvent;
    private volatile bool _realEventSinceClear;
    private volatile bool _contextSwitchPending;

    // Held by DiscardLastSwitchBreak while it rebuilds the queue, by Enqueue and by PendingCount, so a
    // cross-thread count read never sees the transient mid-rebuild count. Never held across a callout.
    private readonly object _rebuildLock = new();

    public int PendingCount
    {
        get { lock (_rebuildLock) return _eventQueue.Count; }
    }

    /// <summary>The last execution status the engine reported (ChangeEngineState), with the flag bits removed.</summary>
    public DEBUG_STATUS LastExecutionStatus => _lastExecutionStatus;

    /// <summary>
    /// True if a breaking event (breakpoint, second-chance exception, system error, or the break that completes
    /// a pending .process /i) occurred since the last ClearBreakingEventFlag call or resume.
    /// </summary>
    public bool HasBreakingEvent => _hasBreakingEvent;

    public void ClearBreakingEventFlag() => _hasBreakingEvent = false;

    /// <summary>
    /// True if a breakpoint hit, second-chance exception or system error broke in since the last
    /// ClearRealEventFlag call or resume. Unlike HasBreakingEvent it is NOT set by the pending
    /// `.process /i` 0x80000003 path, so it tells a real event apart from a bare break.
    /// </summary>
    public bool RealEventSinceClear => _realEventSinceClear;

    public void ClearRealEventFlag() => _realEventSinceClear = false;

    /// <summary>
    /// True after a `.process /i` (invasive context switch) was accepted and before the target has broken back
    /// in. The break that completes the switch arrives as a first-chance STATUS_BREAKPOINT
    /// (nt!RtlpBreakWithStatusInstruction), the same signature as a debugger break-in, so while this is set
    /// that exception must BREAK.
    /// </summary>
    public bool ContextSwitchPending
    {
        get => _contextSwitchPending;
        set => _contextSwitchPending = value;
    }

    // The BreakIn entry the pending-switch path queued during the current kd_continue wait (null if none).
    // DbgEng thread only: callbacks run inside WaitForEvent on that thread.
    private DebugEvent? _lastSwitchBreak;

    /// <summary>Forget the tracked pending-switch BreakIn entry (call before each re-GO).</summary>
    public void ClearLastSwitchBreak() => _lastSwitchBreak = null;

    /// <summary>
    /// Remove from the queue only the BreakIn entry the pending-switch path queued for a stale break that
    /// kd_continue ran past, so it does not resurface in a later kd_wait_for_event. Matched by reference, so no
    /// other (real) event is ever dropped. DbgEng thread only.
    /// </summary>
    public void DiscardLastSwitchBreak()
    {
        var stale = _lastSwitchBreak;
        _lastSwitchBreak = null;
        if (stale == null) return;
        lock (_rebuildLock)
        {
            var n = _eventQueue.Count;
            for (var i = 0; i < n && _eventQueue.TryDequeue(out var evt); i++)
            {
                if (!ReferenceEquals(evt, stale))
                    _eventQueue.Enqueue(evt);
            }
        }
    }

    private void Enqueue(DebugEvent evt)
    {
        lock (_rebuildLock)
        {
            _eventQueue.Enqueue(evt);
            while (_eventQueue.Count > MaxQueuedEvents && _eventQueue.TryDequeue(out _)) { }
        }
    }

    public override HRESULT GetInterestMask(out DEBUG_EVENT_TYPE mask)
    {
        mask = DEBUG_EVENT_TYPE.BREAKPOINT
             | DEBUG_EVENT_TYPE.EXCEPTION
             | DEBUG_EVENT_TYPE.LOAD_MODULE
             | DEBUG_EVENT_TYPE.UNLOAD_MODULE
             | DEBUG_EVENT_TYPE.CREATE_PROCESS
             | DEBUG_EVENT_TYPE.EXIT_PROCESS
             | DEBUG_EVENT_TYPE.SESSION_STATUS
             | DEBUG_EVENT_TYPE.CHANGE_ENGINE_STATE;
        return HRESULT.S_OK;
    }

    public override DEBUG_STATUS Breakpoint(IntPtr bp)
    {
        _hasBreakingEvent = true;
        _realEventSinceClear = true;
        Enqueue(new DebugEvent { Type = DebugEventKind.BreakpointHit, Details = "Breakpoint hit" });
        return DEBUG_STATUS.BREAK;
    }

    public override DEBUG_STATUS Exception(ref EXCEPTION_RECORD64 exception, int firstChance)
    {
        var code = (uint)exception.ExceptionCode;

        if (firstChance != 0 && _contextSwitchPending && code == STATUS_BREAKPOINT)
        {
            // The break-back-in that completes a pending `.process /i` context switch: keep it.
            _hasBreakingEvent = true;
            var switchBreak = new DebugEvent
            {
                Type = DebugEventKind.BreakIn,
                Details = $"Break instruction 0x80000003 at 0x{exception.ExceptionAddress:X16} " +
                          "(first chance) while a .process /i context switch was pending",
            };
            _lastSwitchBreak = switchBreak;
            Enqueue(switchBreak);
            return DEBUG_STATUS.BREAK;
        }

        if (firstChance != 0)
        {
            // First-chance exceptions that reach the kernel debugger include break instructions (DbgBreakPoint,
            // __debugbreak) and assertions (NT_ASSERT) in drivers under test. NO_CHANGE lets the engine's event
            // filters (sx settings) decide whether to break; the default filters break on both. A debugger
            // break-in also arrives here, as a first-chance 0x80000003 at nt!DbgBreakPointWithStatus; the event
            // pump and kd_wait_for_event tell it apart from a hard-coded int 3 by its address and status
            // (DbgEngManager.IsPlainBreakIn).
            var what = code switch
            {
                STATUS_BREAKPOINT => "Break instruction 0x80000003",
                STATUS_ASSERTION_FAILURE => "Assertion failure 0xC0000420",
                _ => $"Exception 0x{code:X8}",
            };
            Enqueue(new DebugEvent
            {
                Type = DebugEventKind.ExceptionFirstChance,
                Details = $"{what} at 0x{exception.ExceptionAddress:X16} (first chance)",
            });
            return DEBUG_STATUS.NO_CHANGE;
        }

        // Second-chance (unhandled) exception: about to become a bugcheck.
        _hasBreakingEvent = true;
        _realEventSinceClear = true;
        Enqueue(new DebugEvent
        {
            Type = DebugEventKind.ExceptionSecondChance,
            Details = $"Exception 0x{code:X8} at 0x{exception.ExceptionAddress:X16} (second chance)",
        });
        return DEBUG_STATUS.BREAK;
    }

    public override DEBUG_STATUS LoadModule(
        long imageFileHandle, long baseOffset, int moduleSize,
        string moduleName, string imageName, int checkSum, int timeDateStamp)
    {
        Enqueue(new DebugEvent
        {
            Type = DebugEventKind.ModuleLoaded,
            Details = $"Module loaded: {moduleName ?? imageName} at 0x{baseOffset:X16}",
        });
        return DEBUG_STATUS.NO_CHANGE;
    }

    public override DEBUG_STATUS UnloadModule(string imageBaseName, long baseOffset)
    {
        Enqueue(new DebugEvent
        {
            Type = DebugEventKind.ModuleUnloaded,
            Details = $"Module unloaded: {imageBaseName} from 0x{baseOffset:X16}",
        });
        return DEBUG_STATUS.NO_CHANGE;
    }

    public override DEBUG_STATUS CreateProcess(
        long imageFileHandle, long handle, long baseOffset, int moduleSize,
        string moduleName, string imageName, int checkSum, int timeDateStamp,
        long initialThreadHandle, long threadDataOffset, long startOffset)
    {
        Enqueue(new DebugEvent { Type = DebugEventKind.ProcessCreated, Details = $"Process created: {moduleName ?? imageName}" });
        return DEBUG_STATUS.NO_CHANGE;
    }

    public override DEBUG_STATUS ExitProcess(int exitCode)
    {
        Enqueue(new DebugEvent { Type = DebugEventKind.ProcessExited, Details = $"Process exited with code {exitCode}" });
        return DEBUG_STATUS.NO_CHANGE;
    }

    public override DEBUG_STATUS CreateThread(long handle, long dataOffset, long startOffset) => DEBUG_STATUS.NO_CHANGE;

    public override DEBUG_STATUS ExitThread(int exitCode) => DEBUG_STATUS.NO_CHANGE;

    public override DEBUG_STATUS SystemError(int error, int level)
    {
        _hasBreakingEvent = true;
        _realEventSinceClear = true;
        Enqueue(new DebugEvent { Type = DebugEventKind.SystemError, Details = $"System error: 0x{error:X8}, level {level}" });
        return DEBUG_STATUS.BREAK;
    }

    public override HRESULT SessionStatus(DEBUG_SESSION status) => HRESULT.S_OK;

    public override HRESULT ChangeDebuggeeState(DEBUG_CDS flags, long argument) => HRESULT.S_OK;

    public override HRESULT ChangeSymbolState(DEBUG_CSS flags, long argument) => HRESULT.S_OK;

    public override HRESULT ChangeEngineState(DEBUG_CES flags, long argument)
    {
        if ((flags & DEBUG_CES.EXECUTION_STATUS) != 0)
        {
            // The argument carries flag bits (for example DEBUG_STATUS_INSIDE_WAIT) above the status itself.
            var st = (DEBUG_STATUS)(argument & (long)DEBUG_STATUS.MASK);
            _lastExecutionStatus = st;

            // A resume (e.g. a breakpoint command ending in `gc`) ends the breaking event, so a later break is
            // not mistaken for it.
            if (st == DEBUG_STATUS.GO || st == DEBUG_STATUS.GO_HANDLED || st == DEBUG_STATUS.GO_NOT_HANDLED)
            {
                _hasBreakingEvent = false;
                _realEventSinceClear = false;
            }
        }
        return HRESULT.S_OK;
    }

    /// <summary>Drain queued events (up to maxCount).</summary>
    public List<DebugEvent> DrainEvents(int maxCount = 50)
    {
        var events = new List<DebugEvent>();
        lock (_rebuildLock)
        {
            while (events.Count < maxCount && _eventQueue.TryDequeue(out var evt))
                events.Add(evt);
        }
        return events;
    }
}
