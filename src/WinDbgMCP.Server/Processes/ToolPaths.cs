using Microsoft.Win32;
using WinDbgMCP.Server.Configuration;

namespace WinDbgMCP.Server.Processes;

/// <summary>
/// Resolves every host program and DLL this server uses to a fully qualified path. A program started by a
/// bare name is searched for by Windows in the server's folder and the current directory before PATH, and an
/// MCP client starts the server in whatever folder its session uses, so a planted ssh.exe there would run as
/// the user. Nothing here returns a relative path.
/// </summary>
public static class ToolPaths
{
    /// <summary>Host.OpenSshPath, else %SystemRoot%\System32\OpenSSH (the Windows OpenSSH client).</summary>
    public static string OpenSshDirectory(HostConfig host) =>
        string.IsNullOrWhiteSpace(host.OpenSshPath)
            ? Path.Combine(Environment.SystemDirectory, "OpenSSH")
            : Environment.ExpandEnvironmentVariables(host.OpenSshPath);

    public static string Ssh(HostConfig host) => Path.Combine(OpenSshDirectory(host), "ssh.exe");

    public static string Scp(HostConfig host) => Path.Combine(OpenSshDirectory(host), "scp.exe");

    /// <summary>
    /// The folders that may hold dbgeng.dll and cdb.exe, in order: Host.DebuggersPath alone when it is set;
    /// otherwise Debuggers\x64 under the installed Windows Kit (KitsRoot10 in HKLM), then under
    /// %ProgramFiles(x86)%\Windows Kits\10.
    /// </summary>
    public static IReadOnlyList<string> DebuggerCandidates(HostConfig host)
    {
        if (!string.IsNullOrWhiteSpace(host.DebuggersPath))
            return new[] { Environment.ExpandEnvironmentVariables(host.DebuggersPath) };

        var list = new List<string>();
        var kits = KitsRoot10();
        if (kits != null) list.Add(Path.Combine(kits, "Debuggers", "x64"));
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "Debuggers", "x64");
        if (!list.Contains(fallback, StringComparer.OrdinalIgnoreCase)) list.Add(fallback);
        return list;
    }

    /// <summary>The first candidate folder that has dbgeng.dll (used for both dbgeng.dll and cdb.exe), or null.</summary>
    public static string? DebuggersDirectory(HostConfig host) =>
        DebuggerCandidates(host).FirstOrDefault(d => Path.IsPathFullyQualified(d) && File.Exists(Path.Combine(d, "dbgeng.dll")));

    /// <summary>cdb.exe next to the dbgeng.dll that kd_* uses, or null.</summary>
    public static string? Cdb(HostConfig host)
    {
        var dir = DebuggersDirectory(host);
        var cdb = dir == null ? null : Path.Combine(dir, "cdb.exe");
        return cdb != null && File.Exists(cdb) ? cdb : null;
    }

    /// <summary>
    /// frida.exe or frida-ps.exe: in Host.FridaToolsPath when it is set, else in the first fully qualified, local
    /// PATH entry that has it. Null when it is not found.
    /// </summary>
    public static string? FridaTool(HostConfig host, string exeName, string? pathVariable = null)
    {
        if (!string.IsNullOrWhiteSpace(host.FridaToolsPath))
        {
            var p = Path.Combine(Environment.ExpandEnvironmentVariables(host.FridaToolsPath), exeName);
            return Path.IsPathFullyQualified(p) && File.Exists(p) ? p : null;
        }
        return SearchPath(exeName, pathVariable ?? Environment.GetEnvironmentVariable("PATH"));
    }

    /// <summary>
    /// Search <paramref name="pathVariable"/> (a PATH value) for <paramref name="exeName"/>. Relative entries
    /// (".", "bin" and so on) and UNC entries are skipped, so the result never depends on the current directory
    /// and the search never opens a network share.
    /// </summary>
    public static string? SearchPath(string exeName, string? pathVariable)
    {
        foreach (var raw in (pathVariable ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dir = Environment.ExpandEnvironmentVariables(raw.Trim('"'));
            if (!Path.IsPathFullyQualified(dir) || dir.StartsWith(@"\\", StringComparison.Ordinal)) continue;
            string candidate;
            try { candidate = Path.GetFullPath(Path.Combine(dir, exeName)); }
            catch { continue; }
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    /// <summary>KitsRoot10 from HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots (64-bit view, then 32-bit), or null.</summary>
    private static string? KitsRoot10()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows Kits\Installed Roots");
                if (key?.GetValue("KitsRoot10") is string s && Path.IsPathFullyQualified(s))
                    return s;
            }
            catch
            {
                // Unreadable key: fall back to the default folder.
            }
        }
        return null;
    }
}
