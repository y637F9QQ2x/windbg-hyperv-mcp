using System.Text;
using ClrDebug;
using ClrDebug.DbgEng;

namespace WinDbgMCP.Server.KernelDebug;

/// <summary>
/// Captures WinDbg command output via IDebugOutputCallbacks. Thread-safe buffer for output from the DbgEng
/// thread. It keeps at most <see cref="MaxChars"/> characters between two reads and counts the rest, so a long
/// wait with chatty breakpoint commands cannot grow it without limit.
/// </summary>
public sealed class OutputCapture : IDebugOutputCallbacks
{
    public const int MaxChars = 4_000_000;

    private readonly StringBuilder _buffer = new();
    private readonly object _lock = new();
    private long _dropped;

    public HRESULT Output(DEBUG_OUTPUT mask, string text)
    {
        lock (_lock)
        {
            var room = MaxChars - _buffer.Length;
            if (text.Length <= room)
            {
                _buffer.Append(text);
            }
            else
            {
                if (room > 0) _buffer.Append(text, 0, room);
                _dropped += text.Length - Math.Max(room, 0);
            }
        }
        return HRESULT.S_OK;
    }

    /// <summary>Get accumulated output and clear the buffer.</summary>
    public string GetAndClear()
    {
        lock (_lock)
        {
            var result = _buffer.ToString();
            if (_dropped > 0)
                result += $"\n[windbg-hyperv-mcp: {_dropped:N0} more characters of debugger output were dropped (buffer limit {MaxChars:N0})]";
            _buffer.Clear();
            _dropped = 0;
            return result;
        }
    }

    /// <summary>Clear the buffer without returning content.</summary>
    public void Clear()
    {
        lock (_lock)
        {
            _buffer.Clear();
            _dropped = 0;
        }
    }
}
