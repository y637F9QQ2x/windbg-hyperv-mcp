using System.Text;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.Processes;
using WinDbgMCP.Server.UserModeDebug;

namespace WinDbgMCP.Tests;

/// <summary>Offline tests of the command lines and parsers. Nothing here starts a process, opens a socket or
/// talks to the Task Scheduler.</summary>
public class LabTaskClientTests
{
    private static readonly DateTime Triggered = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    private static string Result(string started, string? finished = "2026-01-01T12:00:09.0000000Z",
        string ok = "true", string schema = "hvlab-result/1") =>
        "{\"schema\":\"" + schema + "\",\"action\":\"Start\",\"vmName\":\"Test VM\",\"ok\":" + ok + "," +
        "\"message\":\"the VM is Running\",\"stateBefore\":\"Off\",\"stateAfter\":\"Running\"," +
        "\"heartbeat\":\"OkApplicationsUnknown\",\"uptimeSec\":7,\"ipv4\":[\"192.0.2.10\"]," +
        "\"startedUtc\":\"" + started + "\"," +
        "\"finishedUtc\":" + (finished == null ? "null" : "\"" + finished + "\"") + "}";

    [Fact]
    public void ParseResult_ReadsAFinishedRunOfThisTrigger()
    {
        var r = LabTaskClient.ParseResult(Result("2026-01-01T12:00:01.0000000Z"), Triggered);
        Assert.NotNull(r);
        Assert.True(r!.Ok);
        Assert.Equal("Off", r.StateBefore);
        Assert.Equal("Running", r.StateAfter);
        Assert.Equal(new[] { "192.0.2.10" }, r.Ipv4);
        Assert.Equal(7, r.UptimeSec);
        Assert.Contains("VM state Running (before: Off)", r.Describe("Start"));
    }

    [Fact]
    public void ParseResult_IgnoresAnOlderRun()
    {
        Assert.Null(LabTaskClient.ParseResult(Result("2026-01-01T11:59:00.0000000Z"), Triggered));
    }

    [Fact]
    public void ParseResult_AllowsTwoSecondsOfClockSlack()
    {
        Assert.NotNull(LabTaskClient.ParseResult(Result("2026-01-01T11:59:59.0000000Z"), Triggered));
    }

    [Fact]
    public void ParseResult_IgnoresAnUnfinishedRun()
    {
        Assert.Null(LabTaskClient.ParseResult(Result("2026-01-01T12:00:01.0000000Z", finished: null), Triggered));
    }

    [Fact]
    public void ParseResult_ReportsFailure()
    {
        var r = LabTaskClient.ParseResult(Result("2026-01-01T12:00:01.0000000Z", ok: "false"), Triggered);
        Assert.NotNull(r);
        Assert.False(r!.Ok);
        Assert.StartsWith("Start: FAILED", r.Describe("Start"));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1]")]
    [InlineData("{}")]
    public void ParseResult_RejectsBadInput(string json)
    {
        Assert.Null(LabTaskClient.ParseResult(json, Triggered));
    }

    [Fact]
    public void ParseResult_RejectsAForeignSchema()
    {
        Assert.Null(LabTaskClient.ParseResult(Result("2026-01-01T12:00:01.0000000Z", schema: "other/2"), Triggered));
    }

    [Fact]
    public void Paths_FollowTheHostLayout()
    {
        var client = new LabTaskClient("lab1", @"C:\ProgramData\HyperVLpeLab", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        Assert.Equal(@"\HyperVLpeLab\lab1", client.TaskFolder);
        Assert.Equal(@"C:\ProgramData\HyperVLpeLab\lab1\state\TurnOff.json", client.ResultPath("TurnOff"));
    }

    [Fact]
    public async Task UnknownAction_IsRefusedWithoutTouchingTheTaskScheduler()
    {
        var client = new LabTaskClient("lab1", @"C:\ProgramData\HyperVLpeLab", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var r = await client.RunAsync("Delete", 1, CancellationToken.None);
        Assert.False(r.Success);
        Assert.Contains("Unknown lab action", r.Message);
    }
}

public class SshArgumentTests
{
    [Fact]
    public void KnownHostsPath_WithASpace_IsQuoted()
    {
        var args = LabHost.SshBaseArgs(@"C:\Users\John Smith\.ssh\id_ed25519", @"C:\Users\John Smith\.ssh\lab_known_hosts", "accept-new");
        Assert.Contains("UserKnownHostsFile=\"C:\\Users\\John Smith\\.ssh\\lab_known_hosts\"", args);
        Assert.Contains(@"C:\Users\John Smith\.ssh\id_ed25519", args);   // -i is its own argument: no quoting needed
        Assert.Contains("IdentitiesOnly=yes", args);
        Assert.Contains("BatchMode=yes", args);
        Assert.Contains("StrictHostKeyChecking=accept-new", args);
    }

    [Fact]
    public void KeyPath_DoublesPercentSigns()
    {
        // ssh expands % tokens in identity file paths; %% is a literal %.
        var args = LabHost.SshBaseArgs(@"C:\keys\100%\id", @"C:\keys\known_hosts", "yes");
        Assert.Contains(@"C:\keys\100%%\id", args);
    }

    [Fact]
    public void RemoteScpPath_UsesForwardSlashes()
    {
        Assert.Equal("labadmin@192.0.2.10:C:/Windows/Temp/a b.sys",
            LabHost.RemoteScpPath("labadmin", "192.0.2.10", @"C:\Windows\Temp\a b.sys"));
    }

    [Theory]
    [InlineData("", "ssh: connect to host 192.0.2.10 port 22: Connection timed out", true)]
    [InlineData("", "Permission denied (publickey).", true)]
    [InlineData("some output", "Permission denied", false)]   // the remote command ran
    [InlineData("", "", false)]                               // a guest program that exited 255 quietly
    public void Exit255_IsATransportFailureOnlyWhenItLooksLikeOne(string stdout, string stderr, bool expected)
    {
        Assert.Equal(expected, LabHost.LooksLikeSshTransportFailure(new ProcessResult(255, stdout, stderr)));
    }

    [Fact]
    public void ChangedHostKey_GetsTheResetHint()
    {
        var hint = LabHost.KnownHostsHint(new ProcessResult(255, "", "Host key verification failed."));
        Assert.Contains("ssh-keygen -R", hint);
        Assert.Equal("", LabHost.KnownHostsHint(new ProcessResult(255, "", "Connection timed out")));
    }
}

public class GuestCommandTests
{
    [Fact]
    public void Command_SwitchesToUtf8First()
    {
        Assert.Equal("chcp 65001>nul & whoami", GuestExecManager.BuildGuestCommand("whoami", null));
    }

    [Fact]
    public void WorkingDirectory_IsQuotedForCdSlashD()
    {
        Assert.Equal("chcp 65001>nul & cd /d \"C:\\Program Files\\x\" && dir",
            GuestExecManager.BuildGuestCommand("dir", @"C:\Program Files\x"));
    }

    [Fact]
    public void DetachedStart_IsAnEncodedPowerShellCimCall()
    {
        var line = GuestExecManager.BuildDetachedStart("\"C:\\Tools\\frida-server.exe\" -l 192.0.2.10:27042 --token it's");
        Assert.StartsWith(@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ", line);
        var script = Encoding.Unicode.GetString(Convert.FromBase64String(line.Split(' ').Last()));
        Assert.Contains("Invoke-CimMethod -ClassName Win32_Process -MethodName Create", script);
        Assert.Contains("CommandLine = '\"C:\\Tools\\frida-server.exe\" -l 192.0.2.10:27042 --token it''s'", script);
        Assert.DoesNotContain("start /b", line);
    }

    [Fact]
    public void PowerShellDefaultShell_GetsAHint()
    {
        Assert.Contains("DefaultShell", GuestExecManager.ShellHint("... AmpersandNotAllowed ..."));
        Assert.Equal("", GuestExecManager.ShellHint("'x' is not recognized as an internal or external command"));
    }
}

public class FridaArgumentTests
{
    [Fact]
    public void Eval_ByPid()
    {
        Assert.Equal(new[] { "-H", "192.0.2.10:27042", "-p", "1234", "-q", "-t", "1", "-e", "Process.id" },
            FridaManager.BuildEvalArgs("192.0.2.10:27042", 1234, null, "Process.id"));
    }

    [Fact]
    public void Inject_ByName_Eternalized()
    {
        Assert.Equal(new[] { "-H", "192.0.2.10:27042", "-n", "a b.exe", "-q", "-t", "30", "--eternalize", "-l", @"C:\t\s.js" },
            FridaManager.BuildInjectArgs("192.0.2.10:27042", null, "a b.exe", @"C:\t\s.js", 30, eternalize: true));
    }

    [Fact]
    public void Background_RunsUntilStopped()
    {
        Assert.Equal(new[] { "-H", "192.0.2.10:27042", "-p", "7", "-q", "-t", "inf", "-l", @"C:\t\s.js" },
            FridaManager.BuildBackgroundArgs("192.0.2.10:27042", 7, null, @"C:\t\s.js"));
    }

    [Fact]
    public void NameThatLooksLikeAnOption_StaysOneArgument()
    {
        var args = FridaManager.BuildEvalArgs("192.0.2.10:27042", null, "--help", "1");
        Assert.Equal("-n", args[2]);
        Assert.Equal("--help", args[3]);
    }

    [Fact]
    public void Token_GoesInTheEnvironmentNotTheArguments()
    {
        Assert.Null(FridaManager.ToolEnvironment(""));
        Assert.Equal("t0k", FridaManager.ToolEnvironment("t0k")!["FRIDA_TOKEN"]);
        Assert.DoesNotContain(FridaManager.BuildListArgs("192.0.2.10:27042"), a => a.Contains("token"));
    }

    [Fact]
    public void ServerCommandLine_BindsToTheGuestAddress()
    {
        Assert.Equal("\"C:\\Tools\\frida-server.exe\" -l 192.0.2.10:27042",
            FridaManager.BuildServerCommandLine(@"C:\Tools\frida-server.exe", "192.0.2.10", 27042, ""));
        Assert.EndsWith(" --token t0k", FridaManager.BuildServerCommandLine(@"C:\Tools\frida-server.exe", "192.0.2.10", 27042, "t0k"));
    }
}

/// <summary>
/// The one background slot of FridaManager. Host.FridaToolsPath names a folder that does not exist, so
/// frida.exe is never found and nothing is started.
/// </summary>
public class FridaBackgroundSlotTests
{
    private static FridaManager Manager() => new(
        new ServerConfig
        {
            Vm = new VmConfig { GuestIpAddress = "192.0.2.10" },
            Host = new HostConfig
            {
                FridaToolsPath = Path.Combine(Path.GetTempPath(), "windbg-hyperv-mcp-no-frida-" + Guid.NewGuid().ToString("N")),
            },
        },
        Microsoft.Extensions.Logging.Abstractions.NullLogger<FridaManager>.Instance);

    [Fact]
    public async Task SecondStart_IsRefusedWhileTheFirstHoldsTheSlot()
    {
        using var frida = Manager();
        Assert.Null(frida.TryReserveBackgroundStart());   // what a first inject_bg does before it starts frida.exe

        var second = await frida.StartBackgroundAsync(7, null, "1", CancellationToken.None);
        Assert.False(second.Success);
        Assert.Contains("still starting", second.Output);
        Assert.NotNull(frida.TryReserveBackgroundStart());   // the refused call left the slot taken

        frida.ReleaseBackgroundStart();
        Assert.Null(frida.TryReserveBackgroundStart());
        frida.ReleaseBackgroundStart();
    }

    [Fact]
    public async Task FailedStart_FreesTheSlot()
    {
        using var frida = Manager();
        var r = await frida.StartBackgroundAsync(7, null, "1", CancellationToken.None);
        Assert.False(r.Success);
        Assert.Contains("frida.exe was not found", r.Output);
        Assert.Null(frida.TryReserveBackgroundStart());
        frida.ReleaseBackgroundStart();
    }
}

public class DbgsrvArgumentTests
{
    [Fact]
    public void CdbArguments_AreSeparateArguments()
    {
        var args = DbgsrvManager.BuildCdbArguments(DbgsrvManager.BuildTransport("192.0.2.10", 5064, ""), @"srv*C:\s*https://msdl.microsoft.com/download/symbols", 1234, "lm");
        Assert.Equal(new[]
        {
            "-premote", "tcp:port=5064,server=192.0.2.10", "-noshell", "-y", @"srv*C:\s*https://msdl.microsoft.com/download/symbols",
            "-pv", "-p", "1234", "-c", ".echo <<<START>>>; lm; .echo <<<END>>>; q",
        }, args);
    }

    [Fact]
    public void Password_IsAddedToTheTransport()
    {
        Assert.Equal("tcp:port=5064,server=192.0.2.10,password=pw1", DbgsrvManager.BuildTransport("192.0.2.10", 5064, "pw1"));
        Assert.Equal("\"C:\\Tools\\DbgSrv\\dbgsrv.exe\" -t tcp:port=5064,password=pw1",
            DbgsrvManager.BuildServerCommandLine(@"C:\Tools\DbgSrv\dbgsrv.exe", 5064, "pw1"));
    }

    [Fact]
    public void ExtractOutput_UsesTheMarkerLinesNotTheEchoedCommandLine()
    {
        var full = "cdb: Reading initial command '.echo <<<START>>>; lm; .echo <<<END>>>; q'\n" +
                   "<<<START>>>\r\nstart end module name\r\n<<<END>>>\r\nquit:";
        Assert.Equal("start end module name", DbgsrvManager.ExtractOutput(full));
    }

    [Fact]
    public void ExtractOutput_EmptyWhenTheCommandPrintsNothing_NullWhenMarkersMissing()
    {
        Assert.Equal("", DbgsrvManager.ExtractOutput("<<<START>>>\n<<<END>>>\n"));
        Assert.Null(DbgsrvManager.ExtractOutput("no markers here"));
        Assert.Null(DbgsrvManager.ExtractOutput("cdb: Reading initial command '.echo <<<START>>>; lm; .echo <<<END>>>; q'\nUnable to connect"));
    }

    [Fact]
    public void FailureText_HidesThePassword()
    {
        var text = DbgsrvManager.FailureText("Connecting to tcp:port=5064,server=192.0.2.10,password=pw1\nfailed", 1);
        Assert.DoesNotContain("pw1", text);
        Assert.Contains("password=<redacted>", text);
        Assert.Contains("Could not reach dbgsrv", text);
        Assert.StartsWith("cdb.exe exited with code 3 and printed nothing.", DbgsrvManager.FailureText(" \r\n", 3));
    }

    [Fact]
    public void FailureText_RedactsBeforeItCutsTheOutput()
    {
        // The last 2,000 characters start inside the password. A cut before the redaction would keep "7Zq7"
        // and drop the "password=" that the redaction looks for.
        var text = DbgsrvManager.FailureText("password=Zq7Zq7Zq7\n" + new string('y', 1995), 1);
        Assert.StartsWith("...", text);
        Assert.DoesNotContain("Zq7", text);
    }
}

public class TtdCommandTests
{
    [Fact]
    public void Launch_PutsTheOutputFolderBeforeLaunch()
    {
        Assert.Equal("\"C:\\Tools\\TTD\\TTD.exe\" -accepteula -out \"C:\\TTD_Traces\" -launch \"C:\\x\\a.exe\" -v",
            TtdManager.BuildLaunchCommandLine(@"C:\Tools\TTD\TTD.exe", @"C:\TTD_Traces", @"C:\x\a.exe", "-v"));
        Assert.Equal("\"C:\\Tools\\TTD\\TTD.exe\" -accepteula -out \"C:\\TTD_Traces\" -attach 42",
            TtdManager.BuildAttachCommandLine(@"C:\Tools\TTD\TTD.exe", @"C:\TTD_Traces", 42));
    }
}

/// <summary>ToolPaths uses a fresh folder under %TEMP% with an empty fake frida.exe; nothing is started.</summary>
public sealed class ToolPathTests : IDisposable
{
    private readonly string _dir;

    public ToolPathTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "windbg-hyperv-mcp-paths-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "frida.exe"), "");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void PathSearch_SkipsRelativeAndUncEntries()
    {
        var path = string.Join(';', ".", "bin", @"\\server\share", "", _dir);
        var found = ToolPaths.SearchPath("frida.exe", path);
        Assert.Equal(Path.Combine(_dir, "frida.exe"), found);
        Assert.Null(ToolPaths.SearchPath("frida.exe", ".;bin"));
    }

    [Fact]
    public void EveryResolvedProgram_IsFullyQualified()
    {
        var host = new HostConfig();
        Assert.True(Path.IsPathFullyQualified(ToolPaths.Ssh(host)));
        Assert.True(Path.IsPathFullyQualified(ToolPaths.Scp(host)));
        Assert.EndsWith(@"System32\OpenSSH\ssh.exe", ToolPaths.Ssh(host), StringComparison.OrdinalIgnoreCase);
        Assert.All(ToolPaths.DebuggerCandidates(host), d => Assert.True(Path.IsPathFullyQualified(d), d));

        var configured = new HostConfig { FridaToolsPath = _dir, OpenSshPath = _dir };
        Assert.Equal(Path.Combine(_dir, "frida.exe"), ToolPaths.FridaTool(configured, "frida.exe"));
        Assert.Null(ToolPaths.FridaTool(configured, "frida-ps.exe"));   // not in the configured folder: no fallback
        Assert.Equal(Path.Combine(_dir, "ssh.exe"), ToolPaths.Ssh(configured));
    }

    [Fact]
    public void ProcessRunner_RefusesARelativeProgram()
    {
        Assert.Throws<ArgumentException>(() => ProcessRunner.StartInfo("ssh.exe", Array.Empty<string>()));
        Assert.Equal(Environment.SystemDirectory, ProcessRunner.StartInfo(Path.Combine(_dir, "frida.exe"), Array.Empty<string>()).WorkingDirectory);
    }

    [Fact]
    public void BoundedText_KeepsTheStartAndCountsTheRest()
    {
        var t = new BoundedText(5);
        t.Append("abc");
        t.Append("defgh");
        Assert.Equal(3, t.Dropped);
        Assert.StartsWith("abcde\n[windbg-hyperv-mcp: 3 more characters", t.ToString());
    }
}
