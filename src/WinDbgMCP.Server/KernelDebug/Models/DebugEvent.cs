namespace WinDbgMCP.Server.KernelDebug.Models;

public sealed class DebugEvent
{
    public DebugEventKind Type { get; set; }
    public string Details { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public override string ToString() =>
        $"[{Timestamp:HH:mm:ss.fff}] {Type}: {Details}";
}

public enum DebugEventKind
{
    BreakpointHit,
    ExceptionFirstChance,
    ExceptionSecondChance,
    ModuleLoaded,
    ModuleUnloaded,
    ProcessCreated,
    ProcessExited,
    BreakIn,
    SystemError,
}
