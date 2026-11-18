namespace WinDbgMCP.Server.State;

/// <summary>
/// Error messages written for the model. Each one says what happened, why, and what to do next.
/// </summary>
public static class ErrorMessages
{
    // === VM state ===
    public const string VmIsOff =
        "The guest is not reachable on SSH (powered off, paused, booting or off the network). " +
        "Call vm_start to boot the VM, or get_system_state to check again.";

    public const string VmIsPaused =
        "The VM is paused. Call vm_resume to unpause it, then retry.";

    // === Kernel debugger ===
    public const string KdNotConnected =
        "The kernel debugger is not connected. Call kd_connect to attach to the guest kernel.";

    public const string KdAlreadyConnected =
        "The kernel debugger is already connected. Call kd_disconnect first if you need to reconnect.";

    public const string TargetAlreadyBroken =
        "The target is already halted. " +
        "Inspect it with kd_execute (for example 'k', 'r', 'db addr'), or resume it with kd_continue.";

    // === Guest operations ===
    public const string GuestFrozenByKd =
        "The guest is frozen: the kernel debugger holds it at a break, so commands and file transfers " +
        "would hang. Call kd_continue to resume the target, then retry when get_system_state shows " +
        "Guest SSH reachable.";

    public const string GuestSshNotAnswering =
        "The guest SSH service (TCP port 22) is not answering. Possible causes: " +
        "(1) the VM is still booting: call get_system_state again later; " +
        "(2) the guest crashed or lost its network: call get_system_state(queryHost=true); " +
        "(3) sshd is not installed or not running in the guest.";

    // === Connection ===
    public const string KdConnectFailed =
        "Failed to connect the kernel debugger. Check: " +
        "(1) the guest boots with kernel debugging enabled (bcdedit /debug on). " +
        "(2) the KDNET port and key (or the serial pipe name) match the guest. " +
        "(3) no other debugger is attached to this target. " +
        "(4) the host firewall allows the KDNET UDP port inbound.";

    public const string KdOwnedByOtherInstance =
        "kd_connect REFUSED: another instance of this server in this logon session holds the kernel-debug " +
        "session (all instances share one KDNET port and one VM). Call kd_disconnect in the instance that " +
        "connected, or let it exit, then retry. The other tools of this instance are not affected.";

    // === Bugcheck ===
    public static string BsodCannotResume(string? bugcheckCode) =>
        $"Bugcheck {bugcheckCode ?? "(code unknown)"}: the guest OS has crashed and cannot be meaningfully resumed; " +
        "continuing would re-enter the bugcheck handler or hang. Options: " +
        "(1) kd_execute('!analyze -v') to analyze the crash. " +
        "(2) vm_stop(turnOff=true) and then vm_start to reboot the VM.";

    public static string BsodGuestOpsUnavailable(string? bugcheckCode) =>
        $"Bugcheck {bugcheckCode ?? "(code unknown)"}: the guest OS has crashed, so guest tools do not work. " +
        "Options: (1) kd_execute('!analyze -v') to analyze the crash, " +
        "(2) vm_stop(turnOff=true) and then vm_start to reboot.";

    public static string BsodCannotBreak(string? bugcheckCode) =>
        $"Bugcheck {bugcheckCode ?? "(code unknown)"}: the guest OS has crashed and is already halted. " +
        "Use kd_execute('!analyze -v') to investigate, then vm_stop(turnOff=true) and vm_start to recover.";
}
