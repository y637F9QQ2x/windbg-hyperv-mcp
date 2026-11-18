using System.Text.RegularExpressions;

namespace WinDbgMCP.Server.Security;

/// <summary>
/// Refuses debugger commands that act on the HOST rather than on the debug target.
///
/// kd_execute runs DbgEng inside this server process, and umd_dbgsrv runs cdb.exe on the host. In both,
/// some commands reach the host: they start host processes, load host DLLs, read or write host files,
/// open network connections from the host, or run text taken from target memory as commands.
/// With Policy.BlockHostSideEffectCommands (the default) this guard refuses:
///   1. every dot-command at the start of a command that is not in <see cref="AllowedDotCommands"/>, and every
///      other documented dot-command wherever it appears (for example after "j 1 " or "~*e ");
///   2. .reload with a file path;
///   3. script files ($&lt;, $&gt;&lt;, $$&lt;, $$&gt;&lt;, $$&gt;a&lt;), alias definitions (as, aS, r $.u0), source
///      files (lsf), .foreach and the !for_each_* extensions, which read host files or run text that the
///      target controls;
///   4. an extension named with its DLL (!dll.command) unless the DLL is one of <see cref="AllowedExtensionDlls"/>,
///      and the trace-log extension commands *logsave, *tmffile and *searchpath, which use host files;
///   5. the dx helpers that reach the host: Debugger.Utility other than Collections and Code, Debugger.Settings
///      and the extension gallery;
///   6. a UNC or device path (\\server\share, \\?\, \\.\, //server/share) or a URL anywhere: a debugger command
///      has no need for one, and a UNC path makes the host send the user's NTLM credentials to that server.
///
/// The whole string is scanned, quoted breakpoint commands included. It is a text filter, not a sandbox: the
/// security boundary is the Windows account the server runs as (README, "Debugger commands that act on the host").
/// </summary>
public static class HostCommandGuard
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>Dot-commands that only read or change debugger state about the target, or structure other commands.</summary>
    public static readonly IReadOnlySet<string> AllowedDotCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "lastevent", "process", "thread", "context", "cxr", "exr", "ecxr", "trap", "frame", "f+", "f-",
        "bugcheck", "reload", "effmach", "time", "formats", "echo", "printf", "bpcmds",
        "if", "elsif", "else", "for", "while", "do", "break", "continue", "block", "catch", "leave",
    };

    /// <summary>Extension DLLs that may be named in !dll.command. They ship with Debugging Tools for Windows.</summary>
    public static readonly IReadOnlySet<string> AllowedExtensionDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "kdexts", "kext", "ext", "exts", "uext", "ntsdexts", "dbghelp",
    };

    // Every other documented meta-command (Debugger Reference, "Meta-Commands"). These are refused wherever
    // they appear, not only at the start of a command.
    private static readonly HashSet<string> OtherDotCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "abandon", "allow_exec_cmds", "allow_image_mapping", "apply_dbp", "asm", "attach", "breakin", "browse",
        "cache", "call", "chain", "childdbg", "clients", "closehandle", "cls", "cmdtree", "copysym", "cordll",
        "crash", "create", "createdir", "dbgdbg", "detach", "dml_file", "dml_flow", "dml_start", "dump",
        "dumpcab", "dumpdebug", "dvalloc", "dvfree", "echocpunum", "echotime", "echotimestamps",
        "enable_long_status", "enable_unicode", "endpsrv", "endsrv", "enumtag", "event_code", "eventlog",
        "exepath", "expr", "exptr", "extmatch", "extpath", "fiber", "fiximports", "flash_on_break", "fnent",
        "fnret", "force_radix_output", "force_tb", "foreach", "fpo", "help", "hideinjectedcode", "holdmem",
        "idle_cmd", "ignore_missing_pages", "imgscan", "inline", "jdinfo", "kdfiles", "kframes", "kill",
        "lines", "load", "loadby", "locale", "logappend", "logclose", "logfile", "logopen", "lsrcfix",
        "lsrcpath", "netsyms", "netuse", "noshell", "noversion", "nvlist", "nvload", "nvunload",
        "nvunloadall", "ocommand", "ofilter", "open", "opendump", "outmask", "pagein", "pcmd", "pop",
        "prefer_dml", "prompt_allow", "push", "quit_lock", "readmem", "reboot", "record_branches", "remote",
        "remote_exit", "restart", "rrestart", "scriptdebug", "scriptlist", "scriptload", "scriptproviders",
        "scriptrun", "scriptunload", "scroll_prefs", "secure", "send_file", "server", "servers", "setdll",
        "settings", "shell", "show_read_failures", "show_sym_failures", "sleep", "sound_notify", "srcfix",
        "srcnoisy", "srcpath", "step_filter", "suspend_ui", "symfix", "symopt", "sympath", "tlist", "tss",
        "ttime", "typeopt", "unload", "unloadall", "urestart", "wake", "write_cmd_hist", "writemem", "wtitle",
    };

    // A dot-command token. Not after a character that makes it a member access or part of a word or path
    // (dx @$x.Name, (expr).Field, C:\dir\.ssh).
    private static readonly Regex DotToken = new(@"(?<![A-Za-z0-9_)\]$@\\/])\.(?<name>[A-Za-z_][A-Za-z0-9_]*)(?<sign>[+-]?)", Opts);

    // .reload followed by its arguments, up to the end of that command.
    private static readonly Regex ReloadArgs = new(@"(?<![A-Za-z0-9_)\]$@\\/])\.reload\b(?<args>[^;""'{}]*)", Opts);

    // $< $>< $$< $$>< $$>a<  (run a host script file)
    private static readonly Regex ScriptFile = new(@"\$\$?>?a?<", Opts);

    // r $.u0 = text  (a fixed-name alias: its text replaces $u0 in later commands)
    private static readonly Regex FixedAliasSetter = new(@"\$\.u[0-9]", Opts);

    private static readonly Regex UncPath = new(@"\\\\(?=[A-Za-z0-9?.\[$])", Opts);
    private static readonly Regex ForwardUncPath = new(@"(?<![A-Za-z0-9:/])//(?=[A-Za-z0-9.\[])", Opts);
    private static readonly Regex Url = new(@"\b[A-Za-z][A-Za-z0-9+.-]*://", Opts);

    private static readonly Regex ForEachExtension = new(@"!\s*(?:[A-Za-z0-9_]+\.)?for_each_[A-Za-z0-9_]*", Opts);
    private static readonly Regex HostFileExtension = new(@"!\s*(?:[A-Za-z0-9_]+\.)?[A-Za-z0-9_]*(?:logsave|tmffile|searchpath)\b", Opts);

    private static readonly Regex DxUtility = new(@"[.\[""']\s*Utility\b(?!\s*\.\s*(?:Collections|Code)\b)", Opts);
    private static readonly Regex DxSettings = new(@"[.\[""']\s*Settings\b", Opts);
    private static readonly Regex DxGallery = new(@"ExtensionGallery|ExtensionRepositor", Opts);

    // ~*e, ~3e, ~.e, ~#e, ~[expr]e: run the rest of the command for each (or one) thread.
    private static readonly Regex ThreadPrefix = new(@"\G~(?:\*|\.|#|\d+|\[[^\]]*\])e(?=\s|$)", Opts);

    /// <summary>The refused token and why, or null when none is found.</summary>
    public static string? FindHostSideEffect(string? command)
    {
        if (string.IsNullOrEmpty(command)) return null;

        if (DxUtility.Match(command).Success || DxSettings.Match(command).Success || DxGallery.Match(command).Success)
            return "'dx Debugger.Utility / Debugger.Settings' (dx helpers that reach the host; only Debugger.Utility.Collections and .Code are allowed)";
        if (UncPath.Match(command) is { Success: true } unc)
            return Hit(unc, command, "a UNC or device path");
        if (ForwardUncPath.Match(command) is { Success: true } fwd)
            return Hit(fwd, command, "a UNC path");
        if (Url.Match(command) is { Success: true } url)
            return $"'{url.Value}' (a URL)";
        if (ScriptFile.Match(command) is { Success: true } script)
            return $"'{script.Value}' (runs a host script file)";
        if (FixedAliasSetter.Match(command) is { Success: true } alias)
            return $"'{alias.Value}' (an alias definition)";
        if (ForEachExtension.Match(command) is { Success: true } forEach)
            return $"'{forEach.Value}' (runs text taken from the target as commands)";
        if (HostFileExtension.Match(command) is { Success: true } traceFile)
            return $"'{traceFile.Value}' (reads or writes a host file)";

        foreach (Match m in ReloadArgs.Matches(command))
        {
            var args = m.Groups["args"].Value;
            if (args.IndexOfAny(new[] { '\\', ':' }) >= 0)
                return $"'.reload{args.TrimEnd()}' (.reload with a file path)";
        }

        // A documented dot-command outside the allowlist, wherever it appears.
        foreach (Match m in DotToken.Matches(command))
        {
            var name = m.Groups["name"].Value;
            if (OtherDotCommands.Contains(name) && !IsAllowedDot(name, m.Groups["sign"].Value))
                return $"'.{name.ToLowerInvariant()}' (not on the list of allowed dot-commands)";
        }

        // At the start of every command: dot-commands must be on the allowlist; no aliases, no source files,
        // and an extension DLL named in !dll.command must be a known one.
        foreach (var start in CommandStarts(command))
        {
            var reason = CheckCommandStart(command, start);
            if (reason != null) return reason;
        }

        return null;
    }

    /// <summary>Refusal text for <paramref name="toolName"/>, or null when the command may run.</summary>
    public static string? Refusal(string toolName, string? command, bool enabled)
    {
        if (!enabled) return null;
        var hit = FindHostSideEffect(command);
        if (hit == null) return null;
        return $"BLOCKED ({toolName}): {hit} can act on the host computer, not on the debug target. " +
               "Policy.BlockHostSideEffectCommands is on. Allowed dot-commands: " +
               string.Join(" ", AllowedDotCommands.Order(StringComparer.OrdinalIgnoreCase).Select(d => "." + d)) +
               ". Use a command that only inspects the target.";
    }

    private static bool IsAllowedDot(string name, string sign) =>
        AllowedDotCommands.Contains(name + sign) || (sign.Length == 0 && AllowedDotCommands.Contains(name));

    private static string Hit(Match m, string command, string what)
    {
        var end = m.Index;
        while (end < command.Length && !char.IsWhiteSpace(command[end]) && command[end] is not (';' or '"' or '\'')) end++;
        return $"'{command[m.Index..end]}' ({what})";
    }

    /// <summary>Index 0 and the index after every ';', '{', '}', '"' and '\''.</summary>
    private static IEnumerable<int> CommandStarts(string command)
    {
        yield return 0;
        for (var i = 0; i < command.Length; i++)
            if (command[i] is ';' or '{' or '}' or '"' or '\'')
                yield return i + 1;
    }

    private static string? CheckCommandStart(string command, int i)
    {
        while (true)
        {
            while (i < command.Length && char.IsWhiteSpace(command[i])) i++;
            var prefix = ThreadPrefix.Match(command, i);
            if (!prefix.Success) break;
            i += prefix.Length;
        }
        if (i >= command.Length) return null;

        var c = command[i];
        if (c == '.')
        {
            var m = DotToken.Match(command, i);
            if (m.Success && m.Index == i && !IsAllowedDot(m.Groups["name"].Value, m.Groups["sign"].Value))
                return $"'.{m.Groups["name"].Value.ToLowerInvariant()}{m.Groups["sign"].Value}' (not on the list of allowed dot-commands)";
            return null;
        }

        if (c == '!')
        {
            var end = i + 1;
            while (end < command.Length && !char.IsWhiteSpace(command[end]) && command[end] is not (';' or '"' or '\'' or '{' or '}')) end++;
            var name = command[(i + 1)..end];
            var dot = name.LastIndexOf('.');
            if (dot <= 0) return null;   // unqualified: an extension that is already loaded
            var dll = name[..dot];
            if (dll.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || !AllowedExtensionDlls.Contains(dll))
                return $"'!{name}' (extension DLL '{dll}' is not on the list of allowed extension DLLs: " +
                       string.Join(", ", AllowedExtensionDlls.Order(StringComparer.OrdinalIgnoreCase)) + ")";
            return null;
        }

        var wordEnd = i;
        while (wordEnd < command.Length && (char.IsLetterOrDigit(command[wordEnd]) || command[wordEnd] == '-')) wordEnd++;
        var word = command[i..wordEnd];
        if (word.Equals("as", StringComparison.OrdinalIgnoreCase))
            return $"'{word}' (an alias definition: as /ma and similar copy target memory into a command alias)";
        if (word.Equals("lsf", StringComparison.OrdinalIgnoreCase) || word.Equals("lsf-", StringComparison.OrdinalIgnoreCase))
            return $"'{word}' (loads a host source file)";
        return null;
    }
}
