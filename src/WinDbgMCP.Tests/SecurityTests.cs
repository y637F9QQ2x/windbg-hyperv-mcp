using WinDbgMCP.Server.Security;

namespace WinDbgMCP.Tests;

/// <summary>
/// HostPathPolicy tests use a fresh folder under %TEMP% that each test removes again.
/// </summary>
public sealed class HostPathPolicyTests : IDisposable
{
    private readonly string _base;
    private readonly string _root;

    public HostPathPolicyTests()
    {
        _base = Path.Combine(Path.GetTempPath(), "windbg-hyperv-mcp-tests-" + Guid.NewGuid().ToString("N"));
        _root = Path.Combine(_base, "transfer");
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_base, recursive: true); } catch { }
    }

    private string? Check(string path, out string full) => HostPathPolicy.Check(path, new[] { _root }, out full);

    [Fact]
    public void FileInsideRoot_IsAllowed()
    {
        var p = Path.Combine(_root, "sub", "file.bin");
        Assert.Null(Check(p, out var full));
        Assert.Equal(p, full);
    }

    [Fact]
    public void EnvironmentVariables_AreExpandedBeforeTheChecks()
    {
        var name = "WINDBG_HYPERV_MCP_TEST_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, _root);
        try
        {
            Assert.Null(Check($"%{name}%\\file.bin", out var full));
            Assert.Equal(Path.Combine(_root, "file.bin"), full);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void DotDotOutOfRoot_IsRefused()
    {
        Assert.NotNull(Check(Path.Combine(_root, "..", "outside.bin"), out _));
    }

    [Fact]
    public void SiblingWithRootAsPrefix_IsRefused()
    {
        // "transfer-evil" starts with the text "transfer" but is not inside it.
        Assert.NotNull(Check(Path.Combine(_base, "transfer-evil", "x.bin"), out _));
    }

    [Fact]
    public void RootItself_IsRefused()
    {
        Assert.NotNull(Check(_root, out _));
    }

    [Theory]
    [InlineData(@"relative\file.bin")]
    [InlineData(@"-oProxyCommand=calc")]
    [InlineData(@"\\server\share\file.bin")]
    [InlineData(@"\\?\C:\file.bin")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"C:file.bin")]
    [InlineData("")]
    public void NonQualifiedUncAndDevicePaths_AreRefused(string path)
    {
        Assert.NotNull(HostPathPolicy.Check(path, new[] { HostPathPolicy.Unrestricted }, out _));
    }

    [Fact]
    public void AlternateDataStream_IsRefused()
    {
        Assert.NotNull(Check(Path.Combine(_root, "file.bin:stream"), out _));
    }

    [Fact]
    public void Unrestricted_AllowsAnyFullyQualifiedPath()
    {
        Assert.Null(HostPathPolicy.Check(@"C:\anywhere\file.bin", new[] { HostPathPolicy.Unrestricted }, out var full));
        Assert.Equal(@"C:\anywhere\file.bin", full);
    }

    [Fact]
    public void EffectiveRoots_EmptyMeansTheDefaultRoot()
    {
        var roots = HostPathPolicy.EffectiveRoots(new List<string>());
        Assert.Single(roots);
        Assert.Equal(HostPathPolicy.DefaultRoot, roots[0]);
        Assert.EndsWith(Path.Combine("windbg-hyperv-mcp", "transfer"), roots[0]);
    }

    [Fact]
    public void DisplayRoots_DoNotExpandTheProfilePath()
    {
        Assert.Equal(new[] { @"%LOCALAPPDATA%\windbg-hyperv-mcp\transfer" }, HostPathPolicy.DisplayRoots(new List<string>()));
        Assert.Equal(new[] { @"%USERPROFILE%\lab" }, HostPathPolicy.DisplayRoots(new List<string> { @"%USERPROFILE%\lab" }));
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        Assert.Equal(@"%LOCALAPPDATA%\x\y.txt", HostPathPolicy.ForDisplay(Path.Combine(local, "x", "y.txt")));
    }

    /// <summary>
    /// A directory junction (mount point) needs no privilege to create, unlike a symbolic link, so this
    /// test always builds its fixture: a junction inside the root that points outside it.
    /// </summary>
    [Fact]
    public void JunctionInsideRoot_IsRefused()
    {
        var outside = Path.Combine(_base, "outside");
        Directory.CreateDirectory(outside);
        var link = Path.Combine(_root, "link");
        Junction.Create(link, outside);
        try
        {
            Assert.True((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0, "fixture: the junction was not created");

            var refusal = Check(Path.Combine(link, "file.bin"), out _);
            Assert.NotNull(refusal);
            Assert.Contains("reparse point", refusal);
        }
        finally
        {
            // A recursive delete fails on this junction (access denied) and would leave the test folder in
            // %TEMP%, so the junction itself is removed first. This removes the link, not its target.
            Directory.Delete(link);
        }
    }
}

/// <summary>Creates an NTFS directory junction with FSCTL_SET_REPARSE_POINT (test fixture only).</summary>
internal static class Junction
{
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FsctlSetReparsePoint = 0x000900A4;
    private const uint IoReparseTagMountPoint = 0xA0000003;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(Microsoft.Win32.SafeHandles.SafeFileHandle device, uint code, byte[] input,
        int inputSize, IntPtr output, int outputSize, out int returned, IntPtr overlapped);

    public static void Create(string junction, string target)
    {
        Directory.CreateDirectory(junction);
        var substitute = System.Text.Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target));
        var print = System.Text.Encoding.Unicode.GetBytes(Path.GetFullPath(target));

        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms))
        {
            w.Write(IoReparseTagMountPoint);
            w.Write((ushort)(8 + substitute.Length + 2 + print.Length + 2)); // ReparseDataLength
            w.Write((ushort)0);                                              // Reserved
            w.Write((ushort)0);                                              // SubstituteNameOffset
            w.Write((ushort)substitute.Length);
            w.Write((ushort)(substitute.Length + 2));                        // PrintNameOffset
            w.Write((ushort)print.Length);
            w.Write(substitute); w.Write((ushort)0);
            w.Write(print); w.Write((ushort)0);
        }
        var buffer = ms.ToArray();

        using var handle = CreateFileW(junction, GenericWrite, 0, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new System.ComponentModel.Win32Exception();
        if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new System.ComponentModel.Win32Exception();
    }
}

public class HostCommandGuardTests
{
    [Theory]
    // host processes, DLLs and files
    [InlineData(".shell whoami")]
    [InlineData(".SHELL whoami")]
    [InlineData("k; .shell -ci \"r\" findstr x")]
    [InlineData("bp nt!NtCreateFile \".shell calc; gc\"")]   // inside a breakpoint command string
    [InlineData(".load C:\\x\\ext.dll")]
    [InlineData(".loadby sos clr")]
    [InlineData(".extpath C:\\x")]
    [InlineData(".writemem C:\\x\\out.bin 0x1000 L100")]
    [InlineData(".readmem C:\\x\\in.bin 0x1000")]
    [InlineData(".logopen C:\\x\\log.txt")]
    [InlineData(".logappend C:\\x\\log.txt")]
    [InlineData(".dump /ma C:\\x\\a.dmp")]
    [InlineData(".dumpcab C:\\x\\a.cab")]
    [InlineData(".opendump C:\\x\\a.dmp")]
    [InlineData(".kdfiles C:\\x\\map.ini")]
    [InlineData(".cmdtree C:\\x\\tree.txt")]
    [InlineData(".scriptload C:\\x\\s.js")]
    [InlineData(".scriptrun C:\\x\\s.js")]
    [InlineData(".nvload C:\\x\\t.natvis")]
    [InlineData(".settings load C:\\x\\s.xml")]
    [InlineData(".settings save C:\\x\\s.xml")]
    [InlineData(".send_file C:\\x\\id_ed25519 C:\\guest")]
    [InlineData(".copysym C:\\x")]
    [InlineData(".symfix C:\\x")]
    [InlineData(".dbgdbg")]
    [InlineData(".server tcp:port=5005")]
    [InlineData(".server npipe:pipe=x")]
    [InlineData(".ocommand x")]
    [InlineData("lsf C:\\x\\id_ed25519")]
    [InlineData("lsf- C:\\x\\id_ed25519")]
    [InlineData(".reload C:\\x\\nt.sys")]
    [InlineData(".reload /f nt=C:\\x\\nt.sys")]
    [InlineData(".unknowncommand")]                           // not on the allowlist
    // script files and text from the target run as commands
    [InlineData("$<C:\\x\\cmds.txt")]
    [InlineData("$$><C:\\x\\cmds.txt")]
    [InlineData("$$>a<C:\\x\\cmds.txt a b")]
    [InlineData(".foreach /f ( t \"C:\\x\\id_ed25519\" ) { .echo t }")]
    [InlineData("bp nt!Foo \".foreach (t {da 0x1000}) { t }\"")]
    [InlineData("as /ma x 0x1000")]
    [InlineData("aS x \"y\"")]
    [InlineData("r $.u0 = .sh")]
    [InlineData("!for_each_module \".echo @#ModuleName\"")]
    // dot-commands outside the start of a command
    [InlineData("j 1 .shell calc ; k")]
    [InlineData("~*e .shell x")]
    // extensions
    [InlineData("!C:\\x\\evil.cmd")]
    [InlineData("!evil.cmd")]
    [InlineData("!wmitrace.logsave 0 C:\\x\\a.etl")]
    [InlineData("!wdfkd.wdflogsave x C:\\x\\a.etl")]
    // dx helpers that reach the host
    [InlineData("dx Debugger.Utility.FileSystem.CreateFile(\"C:\\\\x\")")]
    [InlineData("dx Debugger.Utility.Control.ExecuteCommand(\"k\")")]
    [InlineData("dx @$u = Debugger.Utility")]
    [InlineData("dx Debugger[\"Utility\"]")]
    [InlineData("dx Debugger.Settings.Symbols")]
    // UNC paths and URLs (an SMB connection sends the user's NTLM response)
    [InlineData(".sympath+ \\\\192.0.2.1\\s")]
    [InlineData(".srcpath \\\\host\\s")]
    [InlineData(".exepath \\\\host\\s")]
    [InlineData(".lsrcpath \\\\host\\s")]
    [InlineData(".reload /f \\\\host\\s\\x.sys")]
    [InlineData("!object \\\\?\\C:\\x")]
    [InlineData(".echo //host/share")]
    [InlineData(".sympath srv*C:\\x*https://example.com")]
    public void HostSideEffectCommands_AreFound(string command)
    {
        Assert.NotNull(HostCommandGuard.FindHostSideEffect(command));
        Assert.NotNull(HostCommandGuard.Refusal("kd_execute", command, enabled: true));
    }

    [Theory]
    [InlineData("k")]
    [InlineData("lm")]
    [InlineData("vertarget")]
    [InlineData("!process 0 0")]
    [InlineData("!kdexts.process 0 0")]
    [InlineData("!ext.analyze -v")]
    [InlineData("!analyze -v")]
    [InlineData(".reload")]
    [InlineData(".reload /f")]
    [InlineData(".reload /f nt")]
    [InlineData(".process /i ffffe001`12345678")]
    [InlineData(".frame /r 2")]
    [InlineData(".f+")]
    [InlineData(".lastevent")]
    [InlineData(".formats 0x10")]
    [InlineData(".printf \"%p\\n\", @rcx")]
    [InlineData("dt nt!_EPROCESS")]
    [InlineData("dx @$curprocess.Threads")]
    [InlineData("dx @$cursession.Processes.Where(p => p.Id == 4).Select(p => p.Name)")]
    [InlineData("dx (*((nt!_EPROCESS*)0xffff800000000000)).ImageFileName")]
    [InlineData("dx Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!PsActiveProcessHead, \"nt!_EPROCESS\", \"ActiveProcessLinks\")")]
    [InlineData("db @rsp L40")]
    [InlineData("? 'A'")]
    [InlineData("bp nt!NtCreateFile \"r rcx; gc\"")]
    [InlineData("bp nt!NtCreateFile \".if (@rcx == 0) { .echo zero } .else { gc }\"")]
    [InlineData(".echo C:\\Users\\x\\.ssh")]
    // file-system names in target commands (an earlier filter refused these)
    [InlineData("!drvobj \\FileSystem\\Ntfs 2")]
    [InlineData("!object \\FileSystem")]
    [InlineData("bp nt!IoRegisterFileSystem")]
    [InlineData("x nt!*FileSystem*")]
    [InlineData("dq nt!IopDiskFileSystemQueueHead L2")]
    [InlineData("")]
    public void TargetOnlyCommands_AreAllowed(string command)
    {
        Assert.Null(HostCommandGuard.FindHostSideEffect(command));
    }

    [Fact]
    public void Refusal_NamesTheAllowedDotCommands()
    {
        var text = HostCommandGuard.Refusal("kd_execute", ".shell whoami", enabled: true);
        Assert.NotNull(text);
        Assert.Contains(".shell", text);
        Assert.Contains(".reload", text);
    }

    [Fact]
    public void Disabled_AllowsEverything()
    {
        Assert.Null(HostCommandGuard.Refusal("kd_execute", ".shell whoami", enabled: false));
    }
}

public class RedactTests
{
    [Theory]
    [InlineData("net:port=50000,key=aaa.bbb.ccc.ddd", "net:port=50000,key=<redacted>")]
    [InlineData("net:port=50000,key=aaa.bbb.ccc.ddd,target=192.0.2.1", "net:port=50000,key=<redacted>,target=192.0.2.1")]
    [InlineData("tcp:port=5064,password=hunter2", "tcp:port=5064,password=<redacted>")]
    [InlineData("com:pipe,port=\\\\.\\pipe\\com_1,resets=0,reconnect", "com:pipe,port=\\\\.\\pipe\\com_1,resets=0,reconnect")]
    [InlineData("", "")]
    public void ConnectionString_HidesSecretValues(string input, string expected)
    {
        Assert.Equal(expected, Redact.ConnectionString(input));
    }

    [Fact]
    public void CommandLine_HidesTheFridaToken()
    {
        Assert.Equal("\"C:\\Tools\\frida-server.exe\" -l 192.0.2.10:27042 --token <redacted>",
            Redact.CommandLine("\"C:\\Tools\\frida-server.exe\" -l 192.0.2.10:27042 --token s3cr3t"));
        Assert.DoesNotContain("pw1", Redact.Arguments(new[] { "-premote", "tcp:port=5064,server=192.0.2.10,password=pw1" }));
    }
}
