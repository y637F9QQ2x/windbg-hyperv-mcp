using System.Net;
using System.Text.RegularExpressions;

namespace WinDbgMCP.Server.Configuration;

public enum KernelDebugPolicy
{
    Attended,
    Enabled,
    Disabled,
}

/// <summary>
/// Validates a bound <see cref="ServerConfig"/> before any service is created. Every value that is later
/// placed on a child-process command line, in a guest command, in a task path or in a DbgEng connection
/// string is checked here, so a bad value stops the server at startup instead of reaching ssh.exe, scp.exe,
/// cdb.exe, the guest or the Task Scheduler. A null value (JSON null) counts as empty.
/// </summary>
public static class ConfigValidator
{
    // A guest account name: letters, digits, '.', '_' and '-', not starting with '-' (an argument that
    // starts with '-' would be parsed as an ssh option).
    private static readonly Regex UserNameRx = new(@"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant);

    // The lab name rule of hyperv-lpe-lab (Test-HvLabName).
    private static readonly Regex LabNameRx = new(@"^[A-Za-z0-9][A-Za-z0-9-]{0,31}$", RegexOptions.CultureInvariant);

    // A KDNET key as bcdedit prints it: four words of letters and digits separated by dots. No ',' can reach
    // the DbgEng connection string, so the key cannot add options to it.
    private static readonly Regex KdnetKeyRx = new(@"^[A-Za-z0-9]+\.[A-Za-z0-9]+\.[A-Za-z0-9]+\.[A-Za-z0-9]+$", RegexOptions.CultureInvariant);

    // A local named pipe only: \\server\pipe\name would make DbgEng open a remote pipe over SMB.
    private static readonly Regex LocalPipeRx = new(@"^\\\\\.\\pipe\\[A-Za-z0-9_.-]{1,200}$", RegexOptions.CultureInvariant);

    // Plain characters only: the token goes into an environment variable and into a guest command line.
    private static readonly Regex FridaTokenRx = new(@"^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant);

    // Microsoft documents a dbgsrv password as "any alphanumeric string, up to twelve characters in length".
    private static readonly Regex DbgsrvPasswordRx = new(@"^[A-Za-z0-9]{1,12}$", RegexOptions.CultureInvariant);

    public static KernelDebugPolicy ParseKernelDebugPolicy(string? value) =>
        ParseByName<KernelDebugPolicy>(value)
        ?? throw new FormatException($"Policy.KernelDebug must be Attended, Enabled or Disabled (got '{value}').");

    /// <summary>Case-insensitive match on the enum member NAMES only (Enum.TryParse would also accept "1").</summary>
    private static T? ParseByName<T>(string? value) where T : struct, Enum
    {
        var v = value?.Trim();
        foreach (var name in Enum.GetNames<T>())
            if (string.Equals(name, v, StringComparison.OrdinalIgnoreCase))
                return Enum.Parse<T>(name);
        return null;
    }

    public static bool IsValidGuestUserName(string? name) => !string.IsNullOrEmpty(name) && UserNameRx.IsMatch(name);

    public static bool IsValidLabName(string? lab) => !string.IsNullOrEmpty(lab) && LabNameRx.IsMatch(lab);

    /// <summary>Vm.InstallRoot with environment variables expanded, or %ProgramData%\HyperVLpeLab when empty.</summary>
    public static string EffectiveInstallRoot(string? configured) =>
        string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HyperVLpeLab")
            : Path.TrimEndingDirectorySeparator(Environment.ExpandEnvironmentVariables(configured));

    /// <summary>Vm.HostPrivateKeyPath with environment variables expanded, or %USERPROFILE%\.ssh\id_ed25519.</summary>
    public static string EffectivePrivateKeyPath(string? configured) =>
        Environment.ExpandEnvironmentVariables(string.IsNullOrWhiteSpace(configured) ? @"%USERPROFILE%\.ssh\id_ed25519" : configured);

    /// <summary>Vm.KnownHostsFile with environment variables expanded, or %USERPROFILE%\.ssh\windbg-hyperv-mcp_known_hosts.</summary>
    public static string EffectiveKnownHostsPath(string? configured) =>
        Environment.ExpandEnvironmentVariables(string.IsNullOrWhiteSpace(configured)
            ? @"%USERPROFILE%\.ssh\windbg-hyperv-mcp_known_hosts" : configured);

    /// <summary>
    /// An IPv4 address literal in dotted-quad form, exactly as IPAddress prints it (no short forms, no
    /// whitespace). IPv6 is not supported: the scp, frida and cdb address forms differ for it.
    /// </summary>
    public static bool IsValidIpAddress(string? ip) =>
        !string.IsNullOrEmpty(ip) && IPAddress.TryParse(ip, out var a) &&
        a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        a.ToString() == ip;

    /// <summary>
    /// Why a known_hosts path cannot be passed to ssh as UserKnownHostsFile="path", or null when it can.
    /// ssh's option parser reads double quotes, so spaces are fine. Newer OpenSSH releases also expand %
    /// tokens in this option and read \\, \" and \' as escapes, so those are refused: a path without them
    /// reads back unchanged in old and new Windows OpenSSH releases alike.
    /// </summary>
    public static string? KnownHostsPathProblem(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
            return "must be a fully qualified local path";
        if (path.IndexOfAny(new[] { '"', '%' }) >= 0)
            return "must not contain \" or %";
        if (path.EndsWith('\\') || path.Contains(@"\\", StringComparison.Ordinal) || path.Contains(@"\'", StringComparison.Ordinal))
            return "must not end with \\ or contain \\\\ or \\'";
        return null;
    }

    /// <summary>Returns every problem found; an empty list means the configuration can be used.</summary>
    public static IReadOnlyList<string> Validate(ServerConfig c)
    {
        var errors = new List<string>();
        static string S(string? v) => v ?? string.Empty;

        // --- VM and SSH ---
        if (string.IsNullOrWhiteSpace(c.Vm.VmName))
            errors.Add("Vm.VmName is empty. Set it to the Hyper-V VM name.");
        if (!IsValidIpAddress(c.Vm.GuestIpAddress))
            errors.Add($"Vm.GuestIpAddress '{S(c.Vm.GuestIpAddress)}' is not an IPv4 address literal.");
        if (!IsValidGuestUserName(c.Vm.GuestUsername))
            errors.Add($"Vm.GuestUsername '{S(c.Vm.GuestUsername)}' is empty or has characters other than letters, digits, '.', '_' and '-'.");
        if (!IsValidLabName(c.Vm.Lab))
            errors.Add($"Vm.Lab '{S(c.Vm.Lab)}' must be the lab name used at host setup: 1-32 letters, digits or hyphens.");
        var installRoot = EffectiveInstallRoot(c.Vm.InstallRoot);
        if (!Path.IsPathFullyQualified(installRoot) || installRoot.StartsWith(@"\\", StringComparison.Ordinal))
            errors.Add($"Vm.InstallRoot '{S(c.Vm.InstallRoot)}' is not a fully qualified local path.");
        if (S(c.Vm.StrictHostKeyChecking) is not ("accept-new" or "yes"))
            errors.Add($"Vm.StrictHostKeyChecking must be \"accept-new\" or \"yes\" (got '{S(c.Vm.StrictHostKeyChecking)}').");

        var key = EffectivePrivateKeyPath(c.Vm.HostPrivateKeyPath);
        if (!Path.IsPathFullyQualified(key) || key.StartsWith(@"\\", StringComparison.Ordinal))
            errors.Add($"Vm.HostPrivateKeyPath '{key}' must be a fully qualified local path.");
        else if (!File.Exists(key))
            errors.Add($"Vm.HostPrivateKeyPath: the key file {key} does not exist. Create the key pair with ssh-keygen and " +
                       "install the public key in the guest, or point Vm.HostPrivateKeyPath at the key you use.");

        var knownHosts = EffectiveKnownHostsPath(c.Vm.KnownHostsFile);
        var khProblem = KnownHostsPathProblem(knownHosts);
        if (khProblem != null)
            errors.Add($"Vm.KnownHostsFile '{knownHosts}' {khProblem}.");
        else if (!Directory.Exists(Path.GetDirectoryName(knownHosts)))
            errors.Add($"Vm.KnownHostsFile: the folder {Path.GetDirectoryName(knownHosts)} does not exist. Create it, or choose another file.");

        // --- Kernel debugging ---
        KernelDebugPolicy? policy = null;
        try { policy = ParseKernelDebugPolicy(c.Policy.KernelDebug); }
        catch (FormatException ex) { errors.Add(ex.Message); }

        var transport = S(c.KernelDebug.Transport);
        var isKdnet = transport.Equals("kdnet", StringComparison.OrdinalIgnoreCase);
        var isSerial = transport.Equals("serial", StringComparison.OrdinalIgnoreCase);
        if (!isKdnet && !isSerial)
            errors.Add($"KernelDebug.Transport must be \"kdnet\" or \"serial\" (got '{transport}').");
        if (c.KernelDebug.Kdnet.Port is < 1 or > 65535)
            errors.Add("KernelDebug.Kdnet.Port must be 1-65535.");
        if (policy != KernelDebugPolicy.Disabled)
        {
            // The key itself is never printed, only whether it has the expected form.
            if (isKdnet && !KdnetKeyRx.IsMatch(S(c.KernelDebug.Kdnet.Key)))
                errors.Add("KernelDebug.Kdnet.Key must be the key that 'bcdedit /dbgsettings' printed in the guest: " +
                           "four words of letters and digits separated by dots.");
            if (isSerial && !LocalPipeRx.IsMatch(S(c.KernelDebug.Serial.PipeName)))
                errors.Add($"KernelDebug.Serial.PipeName '{S(c.KernelDebug.Serial.PipeName)}' must be a local pipe name, " +
                           @"for example \\.\pipe\com_1.");
        }
        var symbolPath = S(c.KernelDebug.SymbolPath);
        if (string.IsNullOrWhiteSpace(symbolPath) || symbolPath.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0)
            errors.Add("KernelDebug.SymbolPath must be a symbol path without quotes or line breaks.");

        // --- Guest ---
        if (c.Guest.FridaPort is < 1 or > 65535)
            errors.Add("Guest.FridaPort must be 1-65535.");
        if (c.Guest.DbgsrvPort is < 1 or > 65535)
            errors.Add("Guest.DbgsrvPort must be 1-65535.");
        foreach (var (name, value) in new (string, string?)[]
                 {
                     ("Guest.FridaServerPath", c.Guest.FridaServerPath), ("Guest.DbgsrvPath", c.Guest.DbgsrvPath),
                     ("Guest.TtdPath", c.Guest.TtdPath), ("Guest.TtdOutputDirectory", c.Guest.TtdOutputDirectory),
                 })
        {
            // These are quoted inside guest command lines.
            if (string.IsNullOrWhiteSpace(value) || value.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0)
                errors.Add($"{name} must be a guest path without quotes or line breaks.");
        }
        if (!string.IsNullOrEmpty(c.Guest.FridaToken) && !FridaTokenRx.IsMatch(c.Guest.FridaToken))
            errors.Add("Guest.FridaToken may only contain letters, digits, '.', '_' and '-' (1-128 characters).");
        if (!string.IsNullOrEmpty(c.Guest.DbgsrvPassword) && !DbgsrvPasswordRx.IsMatch(c.Guest.DbgsrvPassword))
            errors.Add("Guest.DbgsrvPassword must be 1-12 letters or digits (the dbgsrv password rule).");

        // --- Host programs ---
        foreach (var (name, value) in new (string, string?)[]
                 {
                     ("Host.DebuggersPath", c.Host.DebuggersPath), ("Host.FridaToolsPath", c.Host.FridaToolsPath),
                     ("Host.OpenSshPath", c.Host.OpenSshPath),
                 })
        {
            if (string.IsNullOrWhiteSpace(value)) continue;
            var expanded = Environment.ExpandEnvironmentVariables(value);
            if (!Path.IsPathFullyQualified(expanded) || expanded.StartsWith(@"\\", StringComparison.Ordinal))
                errors.Add($"{name} '{value}' must be a fully qualified local folder.");
        }

        // --- Policy ---
        var roots = c.Policy.HostTransferRoots ?? new List<string>();
        foreach (var root in roots)
        {
            if (root == "*") continue;
            var expanded = Environment.ExpandEnvironmentVariables(root ?? "");
            if (string.IsNullOrWhiteSpace(expanded) || !Path.IsPathFullyQualified(expanded) ||
                expanded.StartsWith(@"\\", StringComparison.Ordinal))
                errors.Add($"Policy.HostTransferRoots entry '{root}' is not a fully qualified local path.");
        }
        if (roots.Contains("*") && roots.Count > 1)
            errors.Add("Policy.HostTransferRoots: \"*\" must be the only entry.");

        // --- Limits and timeouts ---
        if (c.Limits.MaxOutputChars is < LimitsConfig.MinOutputChars or > LimitsConfig.MaxOutputCharsLimit)
            errors.Add($"Limits.MaxOutputChars must be {LimitsConfig.MinOutputChars}-{LimitsConfig.MaxOutputCharsLimit} (got {c.Limits.MaxOutputChars}).");

        foreach (var (name, value) in new (string, int)[]
                 {
                     ("VmStartSeconds", c.Timeouts.VmStartSeconds), ("VmStopSeconds", c.Timeouts.VmStopSeconds),
                     ("VmPauseResumeSeconds", c.Timeouts.VmPauseResumeSeconds),
                     ("VmStatusSeconds", c.Timeouts.VmStatusSeconds),
                     ("VmStateQuerySeconds", c.Timeouts.VmStateQuerySeconds),
                     ("KdConnectSeconds", c.Timeouts.KdConnectSeconds),
                     ("KdInitialBreakSeconds", c.Timeouts.KdInitialBreakSeconds),
                     ("KdBreakSeconds", c.Timeouts.KdBreakSeconds), ("KdStepSeconds", c.Timeouts.KdStepSeconds),
                     ("GuestCommandSeconds", c.Timeouts.GuestCommandSeconds),
                     ("GuestFileTransferSeconds", c.Timeouts.GuestFileTransferSeconds),
                 })
        {
            if (value is < 1 or > 3600)
                errors.Add($"Timeouts.{name} must be 1-3600 (got {value}).");
        }

        return errors;
    }
}
