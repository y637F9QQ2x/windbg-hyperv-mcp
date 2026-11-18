namespace WinDbgMCP.Server.Security;

/// <summary>
/// Decides which HOST paths the file-transfer tools may read or write.
///
/// Why: guest_transfer_from_vm writes a file that came from the guest, which this project treats as
/// untrusted, and guest_transfer_to_vm sends a host file into that guest. Without a limit, text the model
/// read from the guest could steer it into writing to a host autostart folder or into sending a host
/// secret (an SSH private key) to the guest. So both directions are confined to configured root folders.
///
/// Rules: environment variables in the path are expanded first; the path must then be fully qualified,
/// must not be a device or UNC path, must not name an alternate data stream, must resolve (after "." and
/// ".." are removed) to a file strictly inside one root, and no existing directory between the root and
/// the file, nor the file itself, may be a reparse point (junction or symbolic link), because a reparse
/// point can redirect the write outside the root.
/// A single root of "*" turns the folder and reparse-point checks off but keeps the other rules.
/// </summary>
public static class HostPathPolicy
{
    public const string Unrestricted = "*";

    /// <summary>Default root when Policy.HostTransferRoots is empty.</summary>
    public static string DefaultRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "windbg-hyperv-mcp", "transfer");

    /// <summary>The default root as shown to the model, without the user's profile path.</summary>
    public const string DefaultRootDisplay = @"%LOCALAPPDATA%\windbg-hyperv-mcp\transfer";

    /// <summary>The configured roots with environment variables expanded; the default root when none is configured.</summary>
    public static IReadOnlyList<string> EffectiveRoots(IReadOnlyList<string>? configured)
    {
        if (configured == null || configured.Count == 0)
            return new[] { DefaultRoot };
        if (configured.Count == 1 && configured[0] == Unrestricted)
            return new[] { Unrestricted };
        return configured.Select(r => Environment.ExpandEnvironmentVariables(r ?? "")).ToArray();
    }

    /// <summary>The roots as written in the configuration (environment variables not expanded), for the model.</summary>
    public static IReadOnlyList<string> DisplayRoots(IReadOnlyList<string>? configured) =>
        configured == null || configured.Count == 0 ? new[] { DefaultRootDisplay } : configured.Select(r => r ?? "").ToArray();

    /// <summary>
    /// The folder where cut tool results are saved: "output" under the first root (under the default root when
    /// the folder check is off).
    /// </summary>
    public static string OutputDirectory(IReadOnlyList<string> effectiveRoots) =>
        Path.Combine(effectiveRoots.Count == 0 || effectiveRoots[0] == Unrestricted ? DefaultRoot : effectiveRoots[0], "output");

    /// <summary>
    /// <paramref name="fullPath"/> with a leading %LOCALAPPDATA% folder written as the variable, so a path shown
    /// to the model does not carry the user's profile path. Other paths are returned unchanged.
    /// </summary>
    public static string ForDisplay(string fullPath)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return !string.IsNullOrEmpty(local) && fullPath.StartsWith(local + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            ? "%LOCALAPPDATA%" + fullPath[local.Length..]
            : fullPath;
    }

    /// <summary>
    /// Validate <paramref name="path"/>. Returns null and the normalized <paramref name="fullPath"/> when the
    /// path is allowed, or an error message that tells the caller which rule failed.
    /// </summary>
    public static string? Check(string? path, IReadOnlyList<string> roots, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
            return "The host path is empty.";
        if (path.IndexOf('\0') >= 0)
            return "The host path contains a NUL character.";
        path = Environment.ExpandEnvironmentVariables(path);
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            return $"UNC and device paths are not allowed: '{path}'.";
        if (!Path.IsPathFullyQualified(path))
            return $"The host path must be fully qualified (for example C:\\folder\\file.bin): '{path}'.";
        if (path.IndexOf(':', 2) >= 0)
            return $"Alternate data streams are not allowed: '{path}'.";

        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) { return $"The host path is not valid ({ex.Message})."; }

        if (roots.Count == 1 && roots[0] == Unrestricted)
        {
            // The operator turned the folder check off; the reparse-point rule only protects a root.
            fullPath = full;
            return null;
        }

        foreach (var rawRoot in roots)
        {
            string root;
            try { root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rawRoot)); }
            catch { continue; }

            if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                continue;

            var reparse = FindReparsePoint(root, full);
            if (reparse != null)
                return $"The host path goes through a reparse point (junction or symbolic link): '{reparse}'.";

            fullPath = full;
            return null;
        }

        return $"The host path '{ForDisplay(full)}' is outside the allowed folders ({string.Join("; ", roots.Select(ForDisplay))}). " +
               "Copy the file into an allowed folder, or add a folder to Policy.HostTransferRoots.";
    }

    /// <summary>
    /// The first existing path element from <paramref name="root"/> (inclusive) down to <paramref name="full"/>
    /// (inclusive) that is a reparse point, or null when there is none.
    /// </summary>
    private static string? FindReparsePoint(string root, string full)
    {
        var current = Path.TrimEndingDirectorySeparator(root);
        var rest = full.Length > current.Length ? full[current.Length..].TrimStart(Path.DirectorySeparatorChar) : "";
        var parts = rest.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);

        if (IsReparsePoint(current)) return current;
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
            if (IsReparsePoint(current)) return current;
        }
        return null;
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            // Path.GetPathRoot ("C:\") is never a reparse point of interest and may be inaccessible.
            if (path.Length <= 3) return false;
            var info = new FileInfo(path);
            if (!info.Exists && !Directory.Exists(path)) return false;
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
}
