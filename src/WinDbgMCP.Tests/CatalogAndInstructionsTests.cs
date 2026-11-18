using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using WinDbgMCP.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Tools;

namespace WinDbgMCP.Tests;

public class ToolCatalogTests
{
    internal static IEnumerable<(MethodInfo Method, McpServerToolAttribute Attr)> ToolsOf(IEnumerable<Type> types) =>
        types.SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
             .Select(m => (m, m.GetCustomAttribute<McpServerToolAttribute>()))
             .Where(x => x.Item2 != null)
             .Select(x => (x.m, x.Item2!));

    private static List<string> Names(ServerConfig c) =>
        ToolsOf(ToolCatalog.Select(c, ConfigValidator.ParseKernelDebugPolicy(c.Policy.KernelDebug)))
            .Select(x => x.Attr.Name!).ToList();

    [Fact]
    public void ToolNames_AreUniqueSnakeCase()
    {
        var names = ToolsOf(ToolCatalog.All).Select(x => x.Attr.Name).ToList();
        Assert.All(names, n => Assert.Matches("^[a-z][a-z0-9_]*$", n!));
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    [Fact]
    public void EveryToolAndParameter_HasADescription()
    {
        foreach (var (method, attr) in ToolsOf(ToolCatalog.All))
        {
            Assert.False(string.IsNullOrWhiteSpace(method.GetCustomAttribute<DescriptionAttribute>()?.Description),
                $"{attr.Name} has no description");
            foreach (var p in method.GetParameters().Where(p => p.ParameterType.IsPrimitive || p.ParameterType == typeof(string) ||
                                                                  p.ParameterType.IsEnum || Nullable.GetUnderlyingType(p.ParameterType) != null))
                Assert.False(string.IsNullOrWhiteSpace(p.GetCustomAttribute<DescriptionAttribute>()?.Description),
                    $"{attr.Name}.{p.Name} has no description");
        }
    }

    [Fact]
    public void EveryTool_SetsAllFourHints()
    {
        // The MCP defaults (destructive, open world) are wrong for most of these tools, so each one sets every
        // hint explicitly. The attribute stores a hint only when its setter ran, which the SDK reports as non-null.
        foreach (var (method, attr) in ToolsOf(ToolCatalog.All))
        {
            var tool = ToolCatalog.CreateTool(method, ToolListSizeTests.Services()).ProtocolTool;
            Assert.NotNull(tool.Annotations);
            Assert.NotNull(tool.Annotations!.ReadOnlyHint);
            Assert.NotNull(tool.Annotations.DestructiveHint);
            Assert.NotNull(tool.Annotations.IdempotentHint);
            Assert.False(tool.Annotations.OpenWorldHint ?? true, $"{attr.Name} must set OpenWorld = false");
        }
    }

    [Fact]
    public void Defaults_Register15Tools()
    {
        var names = Names(new ServerConfig());
        Assert.Equal(15, names.Count);
        Assert.DoesNotContain(names, n => n.Contains("snapshot"));
        Assert.DoesNotContain(names, n => n.StartsWith("umd_"));
        Assert.Contains("kd_connect", names);
    }

    [Fact]
    public void Policies_AddAndRemoveTools()
    {
        var c = new ServerConfig();
        c.Policy.KernelDebug = "Disabled";
        Assert.DoesNotContain(Names(c), n => n.StartsWith("kd_"));
        Assert.Equal(8, Names(c).Count);

        c = new ServerConfig();
        c.Tools.Frida = true;
        c.Tools.Dbgsrv = true;
        c.Tools.Ttd = true;
        var names = Names(c);
        Assert.Equal(18, names.Count);
        Assert.Contains("umd_frida", names);
        Assert.Contains("umd_dbgsrv", names);
        Assert.Contains("umd_ttd", names);
    }

    [Fact]
    public void DescriptionsAndInstructions_UseNoEmOrEnDash()
    {
        foreach (var (method, attr) in ToolsOf(ToolCatalog.All))
        {
            var texts = new[] { method.GetCustomAttribute<DescriptionAttribute>()?.Description ?? "" }
                .Concat(method.GetParameters().Select(p => p.GetCustomAttribute<DescriptionAttribute>()?.Description ?? ""));
            foreach (var t in texts)
                Assert.False(t.Contains('\u2014') || t.Contains('\u2013'), $"{attr.Name}: {t}");
        }
    }
}

public class ServerInstructionsTests
{
    internal static ServerConfig Config()
    {
        var c = new ServerConfig
        {
            Vm = new VmConfig { VmName = "Test VM", GuestIpAddress = "192.0.2.10", GuestUsername = "labadmin", Lab = "lab1" },
        };
        c.KernelDebug.Kdnet.Key = "zz9.plural.zalpha.secret";
        c.Guest.FridaToken = "frida-token-value";
        c.Guest.DbgsrvPassword = "dbgsrvpw1";
        c.Tools.Frida = true;
        c.Tools.Dbgsrv = true;
        return c;
    }

    [Fact]
    public void Instructions_NeverContainSecretsOrTheProfilePath()
    {
        var text = ServerInstructions.Build(Config());
        Assert.DoesNotContain("zz9.plural.zalpha.secret", text);
        Assert.DoesNotContain("key=", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("frida-token-value", text);
        Assert.DoesNotContain("dbgsrvpw1", text);
        Assert.DoesNotContain(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"%LOCALAPPDATA%\windbg-hyperv-mcp\transfer", text);
    }

    [Fact]
    public void HelpTexts_NeverContainSecrets()
    {
        var c = Config();
        foreach (var text in new[] { FridaTools.HelpText(c), DbgsrvTools.HelpText(c) })
        {
            Assert.DoesNotContain("frida-token-value", text);
            Assert.DoesNotContain("dbgsrvpw1", text);
        }
    }

    [Fact]
    public void Attended_IsTheDefaultAndIsStated()
    {
        var text = ServerInstructions.Build(Config());
        Assert.Contains("operator-attended", text);
        Assert.Contains("kd_continue", text);
    }

    [Fact]
    public void DisabledKernelDebug_DropsTheKdRules()
    {
        var c = Config();
        c.Policy.KernelDebug = "Disabled";
        var text = ServerInstructions.Build(c);
        Assert.Contains("Kernel debugging is disabled", text);
        Assert.DoesNotContain("kd_execute", text);
    }

    [Fact]
    public void Instructions_NameTheOutputLimitAndTheBugcheckLine()
    {
        var text = ServerInstructions.Build(Config());
        Assert.Contains("48,000 characters", text);
        Assert.Contains("Bugcheck line", text);
        Assert.Contains("Bugcheck:", MetaTools.Format(new WinDbgMCP.Server.State.SystemState
        {
            KdConnected = true,
            KdExecStatus = WinDbgMCP.Server.State.DebugExecutionStatus.Break,
            IsBugcheck = true,
            BugcheckCode = "0x7e",
        }, null));
    }

    [Fact]
    public void Instructions_DoNotRepeatTheToolCatalog()
    {
        // The client already has every tool description; the instructions stay short.
        var text = ServerInstructions.Build(Config());
        Assert.DoesNotContain("umd_frida", text);
        Assert.True(text.Length < 3000, $"instructions are {text.Length} characters");
    }
}

public class HelpTextTests
{
    private static ServerConfig Setup()
    {
        var c = new ServerConfig();
        c.Vm.GuestIpAddress = "192.0.2.10";
        c.Guest.FridaPort = 27050;
        c.Guest.DbgsrvPort = 5070;
        return c;
    }

    [Fact]
    public void FridaHelp_UsesTheConfiguredAddressAndKeepsLiteralBraces()
    {
        var text = FridaTools.HelpText(Setup());
        Assert.Contains("192.0.2.10:27050", text);
        Assert.Contains("localport=27050 remoteip=<host-ip>", text);
        Assert.Contains("Interceptor.attach(m.getExportByName('CreateFileW'), {", text);
        Assert.DoesNotContain("{{", text);
        Assert.DoesNotContain("{server}", text);
        Assert.DoesNotContain("start /b", text);
        Assert.Contains("Guest.FridaToken", text);
    }

    [Fact]
    public void DbgsrvHelp_UsesTheConfiguredPortAndScopesTheFirewallRule()
    {
        var text = DbgsrvTools.HelpText(Setup());
        Assert.Contains("localport=5070 remoteip=<host-ip>", text);
        Assert.Contains("suspended while each command runs", text);
        Assert.DoesNotContain("start /b", text);
        Assert.DoesNotContain("keeps running. Memory", text);
    }
}

/// <summary>
/// Checks over the repository's own text files: no em or en dash, and no private-range IPv4 address (examples
/// use the RFC 5737 documentation ranges). In a git working tree only the files git tracks are read, so local
/// untracked files never fail the check; without git, the files .gitignore excludes are skipped by name.
/// </summary>
public class RepositoryHygieneTests
{
    private static readonly string[] Extensions = { ".cs", ".md", ".json", ".csproj", ".sln", ".yml", ".yaml", ".gitignore", ".gitattributes", ".editorconfig" };

    private static string? RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "WinDbgMCP.sln")))
            dir = dir.Parent;
        return dir?.FullName;
    }

    private static readonly Regex Ignored = new(
        @"(^|[\\/])(appsettings(?!\.example\.json$)[^\\/]*\.json|windbg-hyperv-mcp[^\\/]*\.json|\.mcp\.json|[^\\/]*\.bak[^\\/]*)$",
        RegexOptions.IgnoreCase);

    internal static IReadOnlyList<string> TextFiles(string root)
    {
        IEnumerable<string> files;
        if (Directory.Exists(Path.Combine(root, ".git")) && GitLsFiles(root) is { } tracked)
            files = tracked.Select(f => Path.Combine(root, f.Replace('/', Path.DirectorySeparatorChar))).Where(File.Exists);
        else
            files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                .Where(p => !p[root.Length..].Split(Path.DirectorySeparatorChar).Any(s => s is "bin" or "obj" or ".git" or ".vs" or "TestResults"))
                .Where(p => !Ignored.IsMatch(p));

        return files.Where(p => Extensions.Contains(Path.GetExtension(p), StringComparer.OrdinalIgnoreCase) ||
                                Path.GetFileName(p) is ".gitignore" or ".gitattributes")
                    .ToList();
    }

    private static string[]? GitLsFiles(string root)
    {
        try
        {
            var psi = new ProcessStartInfo("git", "ls-files -z")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10_000);
            return p.ExitCode == 0 ? output.Split('\0', StringSplitOptions.RemoveEmptyEntries) : null;
        }
        catch
        {
            return null;
        }
    }

    [Fact]
    public void LocalSettingsFiles_AreSkippedWithoutGit()
    {
        Assert.Matches(Ignored, @"C:\repo\src\WinDbgMCP.Server\appsettings.json");
        Assert.Matches(Ignored, @"C:\repo\src\WinDbgMCP.Server\appsettings.json.bak-1");
        Assert.Matches(Ignored, @"C:\repo\.mcp.json");
        Assert.DoesNotMatch(Ignored, @"C:\repo\src\WinDbgMCP.Server\appsettings.example.json");
    }

    [Fact]
    public void NoEmOrEnDashInRepositoryText()
    {
        var root = RepoRoot();
        Assert.NotNull(root);
        var files = TextFiles(root!);
        Assert.NotEmpty(files);
        var hits = files.Where(p => File.ReadAllText(p).IndexOfAny(new[] { '\u2014', '\u2013' }) >= 0).ToList();
        Assert.True(hits.Count == 0, "em/en dash in: " + string.Join(", ", hits));
    }

    [Fact]
    public void NoPrivateRangeIpv4InRepositoryText()
    {
        var root = RepoRoot();
        Assert.NotNull(root);
        var rx = new Regex(@"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])");
        var hits = TextFiles(root!).Where(p => rx.IsMatch(File.ReadAllText(p))).ToList();
        Assert.True(hits.Count == 0, "private IPv4 address in: " + string.Join(", ", hits));
    }
}
