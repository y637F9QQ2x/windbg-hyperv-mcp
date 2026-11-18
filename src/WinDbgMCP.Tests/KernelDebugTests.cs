using ClrDebug.DbgEng;
using Microsoft.Extensions.Logging.Abstractions;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.KernelDebug;
using WinDbgMCP.Server.State;
using WinDbgMCP.Server.Tools;

namespace WinDbgMCP.Tests;

public class ExecutionStatusMappingTests
{
    [Theory]
    [InlineData(DEBUG_STATUS.NO_DEBUGGEE, DebugExecutionStatus.NoDebuggee)]
    [InlineData(DEBUG_STATUS.BREAK, DebugExecutionStatus.Break)]
    [InlineData(DEBUG_STATUS.GO, DebugExecutionStatus.Go)]
    [InlineData(DEBUG_STATUS.GO_HANDLED, DebugExecutionStatus.Go)]
    [InlineData(DEBUG_STATUS.GO_NOT_HANDLED, DebugExecutionStatus.Go)]
    [InlineData(DEBUG_STATUS.STEP_INTO, DebugExecutionStatus.Stepping)]
    [InlineData(DEBUG_STATUS.STEP_OVER, DebugExecutionStatus.Stepping)]
    [InlineData(DEBUG_STATUS.NO_CHANGE, DebugExecutionStatus.Unknown)]
    public void DbgEngStatus_IsMappedByName(DEBUG_STATUS raw, DebugExecutionStatus expected)
    {
        // dbgeng's numbers (NO_DEBUGGEE is 7, BREAK is 6) differ from this server's enum, so a cast would be wrong.
        Assert.Equal(expected, DbgEngManager.MapStatus(raw));
    }
}

public class ConnectionStringTests
{
    [Fact]
    public void Kdnet_UsesTheConfiguredPortAndKey()
    {
        var kd = new KernelDebugConfig { Transport = "kdnet", Kdnet = new KdnetConfig { Port = 50001, Key = "a1.b2.c3.d4" } };
        Assert.Equal("net:port=50001,key=a1.b2.c3.d4", DbgEngManager.BuildConnectionString(kd));
    }

    [Fact]
    public void Serial_UsesTheLocalPipe()
    {
        var kd = new KernelDebugConfig { Transport = "Serial" };
        Assert.Equal(@"com:pipe,port=\\.\pipe\com_1,resets=0,reconnect", DbgEngManager.BuildConnectionString(kd));
    }
}

/// <summary>The DbgEng work thread without DbgEng: plain delegates on its queue.</summary>
public sealed class DbgEngThreadTests : IDisposable
{
    private readonly DbgEngThread _thread = new(NullLogger.Instance) { InterruptGrace = TimeSpan.FromMilliseconds(300) };

    public void Dispose() => _thread.Dispose();

    [Fact]
    public async Task Work_RunsAndReturnsItsResult()
    {
        Assert.Equal(42, await _thread.ExecuteAsync(() => 42, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task QueuedWork_ThatTimesOut_NeverRuns()
    {
        using var release = new ManualResetEventSlim();
        var blocker = _thread.ExecuteAsync(() => { release.Wait(TimeSpan.FromSeconds(10)); return 0; }, TimeSpan.FromSeconds(30));
        var ran = false;
        var queued = _thread.ExecuteAsync(() => { ran = true; return 0; }, TimeSpan.FromMilliseconds(100));

        var ex = await Assert.ThrowsAsync<DbgEngTimeoutException>(() => queued);
        Assert.False(ex.Started);

        release.Set();
        await blocker;
        await _thread.ExecuteAsync(() => 0, TimeSpan.FromSeconds(5));   // the queue has moved past the abandoned item
        Assert.False(ran);
    }

    [Fact]
    public async Task RunningWork_ThatTimesOut_IsInterruptedAndCanStillReturn()
    {
        using var interrupted = new ManualResetEventSlim();
        _thread.InterruptRunningWork = () => interrupted.Set();

        var result = await _thread.ExecuteAsync(() =>
        {
            interrupted.Wait(TimeSpan.FromSeconds(10));   // a command that stops when it is interrupted
            return _thread.CurrentWorkTimedOut ? "interrupted" : "finished";
        }, TimeSpan.FromSeconds(1));   // long enough that the item has surely started when it times out

        Assert.Equal("interrupted", result);
    }

    [Fact]
    public async Task RunningWork_ThatIgnoresTheInterrupt_TimesOutAfterTheGrace()
    {
        using var release = new ManualResetEventSlim();
        var task = _thread.ExecuteAsync(() => { release.Wait(TimeSpan.FromSeconds(10)); return 0; }, TimeSpan.FromSeconds(1));

        var ex = await Assert.ThrowsAsync<DbgEngTimeoutException>(() => task);
        Assert.True(ex.Started);
        release.Set();
    }

    [Fact]
    public async Task WorkQueued_IsCalledForEveryItem()
    {
        var calls = 0;
        _thread.WorkQueued = () => Interlocked.Increment(ref calls);
        await _thread.ExecuteAsync(() => 1, TimeSpan.FromSeconds(5));
        await _thread.ExecuteAsync(() => 2, TimeSpan.FromSeconds(5));
        Assert.Equal(2, calls);
    }
}

public class ToolOutputTests
{
    private static ToolOutput Output(int max = LimitsConfig.MinOutputChars, string? root = null)
    {
        var c = new ServerConfig();
        c.Limits.MaxOutputChars = max;
        if (root != null) c.Policy.HostTransferRoots.Add(root);
        return new ToolOutput(c, NullLogger<ToolOutput>.Instance);
    }

    [Fact]
    public void ShortText_IsReturnedUnchanged()
    {
        var r = Output().Ok("kd_execute", "abc");
        Assert.False(r.IsError);
        Assert.Equal("abc", r.Content.Single().Text);
        Assert.True(Output().Error("kd_execute", "nope").IsError);
    }

    [Fact]
    public void LongText_IsCutAtALineAndSavedInFull()
    {
        var root = Path.Combine(Path.GetTempPath(), "windbg-hyperv-mcp-output-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var text = string.Concat(Enumerable.Range(0, 2000).Select(i => $"line {i:D5}\n"));   // 22,000 characters
            var bounded = Output(LimitsConfig.MinOutputChars, root).Ok("kd_execute", text).Content.Single().Text!;

            Assert.True(bounded.Length <= LimitsConfig.MinOutputChars, $"{bounded.Length} characters");
            Assert.Contains("[windbg-hyperv-mcp: the result was cut after", bounded);
            Assert.Contains($"of {text.Length:N0} characters", bounded);
            var kept = bounded[..bounded.IndexOf("\n\n[windbg-hyperv-mcp", StringComparison.Ordinal)];
            Assert.EndsWith("\n" + kept.Split('\n').Last(), kept);   // whole lines only
            Assert.Matches(@"^line \d{5}$", kept.Split('\n').Last());

            var saved = Directory.GetFiles(Path.Combine(root, "output"));
            Assert.Single(saved);
            Assert.Equal(text, File.ReadAllText(saved[0]));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void CutPoint_PrefersALineBreak()
    {
        Assert.Equal(9, ToolOutput.CutPoint("aaaa bbbb\ncccc", 12));
        Assert.Equal(5, ToolOutput.CutPoint("aaaaaaaaaaaaaaaa", 5));   // no line break: cut at the limit
    }
}
