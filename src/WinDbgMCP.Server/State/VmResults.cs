using WinDbgMCP.Server.HyperV;

namespace WinDbgMCP.Server.State;

/// <summary>Result of a VM lifecycle operation.</summary>
public sealed class VmResult
{
    /// <summary>The task reported success, or (when <see cref="IsPending"/>) it is still running.</summary>
    public bool Success { get; }

    /// <summary>The task started but had not reported a result when the server stopped waiting.</summary>
    public bool IsPending { get; }

    public string Message { get; }

    /// <summary>What the host worker reported (VM state before and after, heartbeat, IPv4), when it reported.</summary>
    public LabTaskResult? Host { get; }

    private VmResult(bool success, bool pending, string message, LabTaskResult? host)
    {
        Success = success;
        IsPending = pending;
        Message = message;
        Host = host;
    }

    public static VmResult Ok(string message, LabTaskResult? host = null) => new(true, false, message, host);
    public static VmResult Pending(string message) => new(true, true, message, null);
    public static VmResult Failed(string message, LabTaskResult? host = null) => new(false, false, message, host);
}
