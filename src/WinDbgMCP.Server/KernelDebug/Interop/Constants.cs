using System.Text.RegularExpressions;

namespace WinDbgMCP.Server.KernelDebug.Interop;

/// <summary>
/// The command check of kd_execute.
/// </summary>
public static class DbgEngConstants
{
    /// <summary>
    /// Commands that kd_execute refuses. They would resume the target (or end the session) outside
    /// kd_continue, kd_step and kd_disconnect, and the server would lose track of the target's state.
    /// Engine-level backstops cover what this text check cannot see (for example a 'g' inside .if): see
    /// DbgEngManager.ExecuteCommandAsync.
    /// </summary>
    public static readonly HashSet<string> BlockedCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        // Go variants
        "g", "gc", "gh", "gn", "gu",
        // Trace and step variants
        "t", "p",
        "ta", "pa",
        "tc", "pc",
        "tt", "pt",
        "th", "ph",
        "tb", "tct", "pct",
        "wt",
        // Session end
        "q", "qq", "qd",
        ".detach",
        ".restart",
        ".reboot",
    };

    // The command name at the start of one command: letters, optionally after a dot. "g@$ra" and "g\t@$ra"
    // both read as "g".
    private static readonly Regex CommandName = new(@"^\s*(?<name>\.?[A-Za-z]+)", RegexOptions.CultureInvariant);

    /// <summary>
    /// Checks every command of a compound command line ("bp foo; g") and commands with arguments ("g @$ra").
    /// Compound commands are split on ';' outside double quotes only: a breakpoint command string such as
    /// bp addr "r rcx; gc" is run by the engine at the hit, not by kd_execute.
    /// </summary>
    public static (bool IsBlocked, string BlockedCmd, string Suggestion) CheckCommand(string command)
    {
        var parts = Regex.Split(command, ";(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

        foreach (var part in parts)
        {
            var m = CommandName.Match(part);
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            if (!BlockedCommands.Contains(name)) continue;

            var suggestion = name.ToLowerInvariant() switch
            {
                "g" or "gc" or "gh" or "gn"
                    => "Use kd_continue instead.",
                "gu"
                    => "Use kd_continue instead. To run until the function returns, set a breakpoint on the return " +
                       "address first: kd_execute('bp @$ra'), then kd_continue.",
                "t" or "ta" or "tc" or "tt" or "th" or "tb" or "tct"
                    => "Use kd_step(mode='into') instead.",
                "p" or "pa" or "pc" or "pt" or "ph" or "pct"
                    => "Use kd_step(mode='over') instead.",
                "wt"
                    => "Use kd_step(mode='over') for single steps, or set a breakpoint and call kd_continue.",
                "q" or "qq" or "qd"
                    => "Use kd_disconnect to end the debug session.",
                ".detach"
                    => "Use kd_disconnect to detach.",
                ".restart" or ".reboot"
                    => "Use vm_stop and then vm_start to restart the guest.",
                _ => "Use the dedicated kd_* tool instead.",
            };

            return (true, name, suggestion);
        }

        return (false, "", "");
    }
}
