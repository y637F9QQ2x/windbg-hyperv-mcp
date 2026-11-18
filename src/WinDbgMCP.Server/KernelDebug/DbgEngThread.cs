using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace WinDbgMCP.Server.KernelDebug;

/// <summary>
/// Dedicated thread for ALL DbgEng COM operations. DbgEng has strict thread affinity: all calls must happen
/// on the thread that called DebugCreate (SetInterrupt and GetInterrupt are documented exceptions and may be
/// called from any thread). This class marshals work items to that thread and, while no work is queued and the
/// target runs, lets DbgEngManager pump debug events.
///
/// Timeouts: a work item that has not started when its timeout passes never runs, and the caller gets a
/// <see cref="DbgEngTimeoutException"/> with Started = false. A work item that is running when its timeout
/// passes is asked to stop (<see cref="InterruptRunningWork"/>, which DbgEngManager maps to
/// SetInterrupt(DEBUG_INTERRUPT_ACTIVE): on a halted target that aborts the running command). If it finishes
/// within <see cref="InterruptGrace"/>, the caller gets its result and the work item can tell from
/// <see cref="CurrentWorkTimedOut"/> that it was interrupted; otherwise the caller gets a
/// <see cref="DbgEngTimeoutException"/> with Started = true while the thread stays busy with it.
/// </summary>
public sealed class DbgEngThread : IDisposable
{
    private readonly Thread _thread;
    private readonly BlockingCollection<WorkItem> _workQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger _logger;
    private volatile bool _disposed;
    private volatile WorkItem? _current;

    /// <summary>Set by DbgEngManager: one event-pump iteration, run while no work is queued.</summary>
    public Action? PumpEventsAction { get; set; }

    /// <summary>Whether event pumping is enabled (only while the target runs). Set on this thread only.</summary>
    public volatile bool PumpEnabled;

    /// <summary>Called on the queuing thread right after a work item is queued (the event pump ends its wait).</summary>
    public Action? WorkQueued { get; set; }

    /// <summary>Called on a timer thread when a running work item passes its timeout.</summary>
    public Action? InterruptRunningWork { get; set; }

    /// <summary>How long an interrupted work item may take to finish before its caller stops waiting.</summary>
    public TimeSpan InterruptGrace { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>True while a work item is queued and has not started.</summary>
    public bool HasPendingWork => _workQueue.Count > 0;

    /// <summary>
    /// True when the work item running on this thread has passed its timeout and was interrupted. Read it on
    /// this thread, inside the work item.
    /// </summary>
    public bool CurrentWorkTimedOut => _current?.TimedOut == true;

    public DbgEngThread(ILogger logger)
    {
        _logger = logger;
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "DbgEng-Thread",
        };
        _thread.SetApartmentState(ApartmentState.MTA);
        _thread.Start();
    }

    private void Run()
    {
        _logger.LogInformation("DbgEng thread started (ThreadId={ThreadId})", Environment.CurrentManagedThreadId);

        while (!_cts.IsCancellationRequested)
        {
            // Queued tool calls first. With the pump off, block on the queue (no polling); with it on, look and
            // go back to pumping at once.
            WorkItem? work;
            try
            {
                var pumping = PumpEnabled && PumpEventsAction != null;
                if (!_workQueue.TryTake(out work, pumping ? 0 : 250, _cts.Token))
                    work = null;
            }
            catch (OperationCanceledException) { break; }
            catch (InvalidOperationException) { break; }   // CompleteAdding was called

            if (work != null)
            {
                Execute(work);
                continue;
            }

            if (PumpEnabled && PumpEventsAction != null)
            {
                try
                {
                    PumpEventsAction();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Event pump iteration failed");
                }
            }
        }

        _logger.LogInformation("DbgEng thread exiting");
    }

    private void Execute(WorkItem work)
    {
        if (!work.TryStart()) return;   // its caller already gave up while it was queued
        _current = work;
        try
        {
            work.Run();
        }
        catch (Exception ex)
        {
            // Run() completes its own task; this only catches a failure outside it.
            _logger.LogError(ex, "Work item failed on DbgEng thread");
        }
        finally
        {
            _current = null;
            work.MarkDone();
        }
    }

    /// <summary>Execute a function on the DbgEng thread and return the result.</summary>
    public Task<T> ExecuteAsync<T>(Func<T> work, TimeSpan timeout)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(DbgEngThread));

        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var item = new WorkItem(() =>
        {
            try
            {
                tcs.TrySetResult(work());
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        });

        var timer = new Timer(_ => OnTimeout(item, tcs, timeout), null, timeout, Timeout.InfiniteTimeSpan);
        _ = tcs.Task.ContinueWith(_ => timer.Dispose(),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

        _workQueue.Add(item);
        try { WorkQueued?.Invoke(); }
        catch (Exception ex) { _logger.LogDebug(ex, "WorkQueued hook failed"); }
        return tcs.Task;
    }

    /// <summary>Execute a void action on the DbgEng thread.</summary>
    public Task ExecuteAsync(Action work, TimeSpan timeout) =>
        ExecuteAsync<object?>(() => { work(); return null; }, timeout);

    private void OnTimeout<T>(WorkItem item, TaskCompletionSource<T> tcs, TimeSpan timeout)
    {
        if (item.TryAbandon())
        {
            tcs.TrySetException(new DbgEngTimeoutException(started: false, timeout));
            return;
        }
        if (item.IsDone) return;

        item.TimedOut = true;
        try { InterruptRunningWork?.Invoke(); }
        catch (Exception ex) { _logger.LogDebug(ex, "InterruptRunningWork hook failed"); }

        _ = Task.Delay(InterruptGrace).ContinueWith(_ =>
        {
            if (!item.IsDone)
                tcs.TrySetException(new DbgEngTimeoutException(started: true, timeout));
        }, TaskScheduler.Default);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _workQueue.CompleteAdding();

        if (_thread.IsAlive)
            _thread.Join(TimeSpan.FromSeconds(5));

        _cts.Dispose();
        _workQueue.Dispose();
    }

    private sealed class WorkItem
    {
        private const int Queued = 0, Running = 1, Done = 2, Abandoned = 3;
        private readonly Action _action;
        private int _state;

        public WorkItem(Action action) => _action = action;

        public volatile bool TimedOut;

        public bool IsDone => Volatile.Read(ref _state) == Done;

        public bool TryStart() => Interlocked.CompareExchange(ref _state, Running, Queued) == Queued;

        public bool TryAbandon() => Interlocked.CompareExchange(ref _state, Abandoned, Queued) == Queued;

        public void MarkDone() => Volatile.Write(ref _state, Done);

        public void Run() => _action();
    }
}

/// <summary>A DbgEng work item that did not finish within its timeout.</summary>
public sealed class DbgEngTimeoutException : TimeoutException
{
    public DbgEngTimeoutException(bool started, TimeSpan timeout)
        : base(started
            ? $"The debugger call did not finish within {timeout.TotalSeconds:0} s and did not stop when interrupted. " +
              "The DbgEng thread is still busy with it; later kd_* calls wait behind it. If they keep timing out, restart the MCP server."
            : $"The debugger call did not start within {timeout.TotalSeconds:0} s because the DbgEng thread was busy with an earlier call.")
    {
        Started = started;
    }

    public bool Started { get; }
}
