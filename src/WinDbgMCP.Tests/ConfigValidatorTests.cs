using WinDbgMCP.Server.Configuration;

namespace WinDbgMCP.Tests;

/// <summary>Uses a fresh folder under %TEMP% (a key file and a known_hosts folder) that each test removes again.</summary>
public sealed class ConfigValidatorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _key;

    public ConfigValidatorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "windbg-hyperv-mcp-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _key = Path.Combine(_dir, "id_test");
        File.WriteAllText(_key, "not a real key");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // RFC 5737 documentation address (TEST-NET-1).
    private ServerConfig Valid()
    {
        var c = new ServerConfig
        {
            Vm = new VmConfig
            {
                VmName = "Test VM", GuestIpAddress = "192.0.2.10", GuestUsername = "labadmin", Lab = "lab1",
                HostPrivateKeyPath = _key, KnownHostsFile = Path.Combine(_dir, "known_hosts"),
            },
        };
        c.KernelDebug.Kdnet.Key = "abc1.def2.ghi3.jkl4";
        return c;
    }

    [Fact]
    public void ValidConfig_HasNoErrors()
    {
        Assert.Empty(ConfigValidator.Validate(Valid()));
    }

    [Fact]
    public void Defaults_AreTheDocumentedOnes()
    {
        var c = new ServerConfig();
        Assert.Equal("Attended", c.Policy.KernelDebug);
        Assert.True(c.Policy.BlockHostSideEffectCommands);
        Assert.Empty(c.Policy.HostTransferRoots);
        Assert.Equal("", c.Vm.InstallRoot);
        Assert.Equal("accept-new", c.Vm.StrictHostKeyChecking);
        Assert.False(c.Tools.Frida);
        Assert.False(c.Tools.Dbgsrv);
        Assert.False(c.Tools.Ttd);
        Assert.Equal(48_000, c.Limits.MaxOutputChars);
        Assert.Equal(45, c.Timeouts.GuestCommandSeconds);
        Assert.StartsWith(@"srv*%LOCALAPPDATA%\windbg-hyperv-mcp\symbols*", c.KernelDebug.SymbolPath);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-ip")]
    [InlineData("192.0.2")]          // IPAddress.TryParse accepts this short form; the validator does not
    [InlineData("2001:db8::10")]     // IPv6 is not supported
    [InlineData("192.0.2.10 ")]
    public void GuestIp_MustBeAnIpv4Literal(string ip)
    {
        var c = Valid();
        c.Vm.GuestIpAddress = ip;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("GuestIpAddress"));
    }

    [Theory]
    [InlineData("-oProxyCommand=calc")]   // would be parsed as an ssh option
    [InlineData("user name")]
    [InlineData("user@host")]
    [InlineData("")]
    [InlineData("a\"b")]
    public void GuestUsername_RejectsValuesThatCouldReachTheSshCommandLine(string user)
    {
        var c = Valid();
        c.Vm.GuestUsername = user;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("GuestUsername"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("-lab")]
    [InlineData("lab 1")]
    [InlineData(@"lab\..\x")]
    [InlineData("lab_1")]
    [InlineData("a234567890123456789012345678901234")]   // 34 characters
    public void Lab_FollowsTheHostAutomationRule(string lab)
    {
        var c = Valid();
        c.Vm.Lab = lab;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("Vm.Lab"));
    }

    [Fact]
    public void InstallRoot_DefaultsToProgramData()
    {
        var root = ConfigValidator.EffectiveInstallRoot("");
        Assert.EndsWith("HyperVLpeLab", root);
        Assert.True(Path.IsPathFullyQualified(root));
    }

    [Theory]
    [InlineData(@"relative\folder")]
    [InlineData(@"\\server\share\HyperVLpeLab")]   // the result files would be read over SMB
    public void InstallRoot_MustBeAFullyQualifiedLocalPath(string root)
    {
        var c = Valid();
        c.Vm.InstallRoot = root;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("InstallRoot"));
    }

    [Fact]
    public void MissingKeyFile_IsAnError()
    {
        var c = Valid();
        c.Vm.HostPrivateKeyPath = Path.Combine(_dir, "no-such-key");
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("HostPrivateKeyPath"));
    }

    [Theory]
    [InlineData(@"relative\known_hosts")]
    [InlineData(@"\\server\share\known_hosts")]
    [InlineData(@"C:\a%d\known_hosts")]          // ssh expands % tokens
    [InlineData(@"C:\a\'b\known_hosts")]         // \' is an escape in newer ssh option parsing
    [InlineData("C:\\a\"b\\known_hosts")]
    public void KnownHostsPath_RejectsWhatSshWouldReadDifferently(string path)
    {
        Assert.NotNull(ConfigValidator.KnownHostsPathProblem(path));
    }

    [Fact]
    public void KnownHostsPath_WithSpacesAndApostrophe_IsAccepted()
    {
        Assert.Null(ConfigValidator.KnownHostsPathProblem(@"C:\Users\John O'Brien Smith\.ssh\windbg-hyperv-mcp_known_hosts"));
    }

    [Fact]
    public void KnownHostsFolder_MustExist()
    {
        var c = Valid();
        c.Vm.KnownHostsFile = Path.Combine(_dir, "missing-folder", "known_hosts");
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("KnownHostsFile"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc1.def2.ghi3")]
    [InlineData("a.b.c.d,target=192.0.2.1")]   // would add an option to the DbgEng connection string
    [InlineData("<key printed by bcdedit /dbgsettings in the guest>")]
    public void KdnetKey_MustLookLikeABcdeditKey(string key)
    {
        var c = Valid();
        c.KernelDebug.Kdnet.Key = key;
        var errors = ConfigValidator.Validate(c);
        Assert.Contains(errors, e => e.Contains("Kdnet.Key"));
        Assert.DoesNotContain(errors, e => key.Length > 0 && e.Contains(key));   // the key value is never printed
    }

    [Fact]
    public void KdnetKey_IsNotNeededWhenKernelDebuggingIsDisabled()
    {
        var c = Valid();
        c.KernelDebug.Kdnet.Key = "";
        c.Policy.KernelDebug = "Disabled";
        Assert.Empty(ConfigValidator.Validate(c));
    }

    [Theory]
    [InlineData(@"\\server\pipe\com_1")]   // a remote pipe over SMB
    [InlineData(@"\\.\pipe\com 1")]
    [InlineData("")]
    public void SerialPipe_MustBeALocalPipe(string pipe)
    {
        var c = Valid();
        c.KernelDebug.Transport = "serial";
        c.KernelDebug.Serial.PipeName = pipe;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("PipeName"));
    }

    [Theory]
    [InlineData("Host.DebuggersPath")]
    [InlineData("Host.FridaToolsPath")]
    [InlineData("Host.OpenSshPath")]
    public void HostProgramFolders_MustBeFullyQualified(string key)
    {
        var c = Valid();
        switch (key)
        {
            case "Host.DebuggersPath": c.Host.DebuggersPath = @"tools\debuggers"; break;
            case "Host.FridaToolsPath": c.Host.FridaToolsPath = "."; break;
            default: c.Host.OpenSshPath = @"\\server\openssh"; break;
        }
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains(key));
    }

    [Theory]
    [InlineData("with space")]
    [InlineData("a\"b")]
    public void FridaToken_IsPlainCharacters(string token)
    {
        var c = Valid();
        c.Guest.FridaToken = token;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("FridaToken"));
    }

    [Theory]
    [InlineData("thirteenchars")]   // 13: dbgsrv allows up to 12
    [InlineData("pass,word")]
    public void DbgsrvPassword_FollowsTheDbgsrvRule(string password)
    {
        var c = Valid();
        c.Guest.DbgsrvPassword = password;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("DbgsrvPassword"));
    }

    [Theory]
    [InlineData(7_999)]
    [InlineData(500_001)]
    public void MaxOutputChars_HasARange(int value)
    {
        var c = Valid();
        c.Limits.MaxOutputChars = value;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("MaxOutputChars"));
    }

    [Fact]
    public void NullStrings_AreReportedNotThrown()
    {
        var c = Valid();
        c.KernelDebug.Transport = null!;
        c.Vm.StrictHostKeyChecking = null!;
        var errors = ConfigValidator.Validate(c);
        Assert.Contains(errors, e => e.Contains("Transport"));
        Assert.Contains(errors, e => e.Contains("StrictHostKeyChecking"));
    }

    [Theory]
    [InlineData("attended", KernelDebugPolicy.Attended)]
    [InlineData("Enabled", KernelDebugPolicy.Enabled)]
    [InlineData("DISABLED", KernelDebugPolicy.Disabled)]
    public void KernelDebugPolicy_ParsesCaseInsensitively(string value, KernelDebugPolicy expected)
    {
        Assert.Equal(expected, ConfigValidator.ParseKernelDebugPolicy(value));
    }

    [Theory]
    [InlineData("on")]
    [InlineData("1")]
    [InlineData("")]
    public void KernelDebugPolicy_RejectsUnknownValues(string value)
    {
        Assert.Throws<FormatException>(() => ConfigValidator.ParseKernelDebugPolicy(value));
    }

    [Fact]
    public void HostTransferRoots_MustBeFullyQualified()
    {
        var c = Valid();
        c.Policy.HostTransferRoots.Add(@"relative\folder");
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("HostTransferRoots"));
    }

    [Fact]
    public void HostTransferRoots_StarMustBeAlone()
    {
        var c = Valid();
        c.Policy.HostTransferRoots.Add("*");
        Assert.Empty(ConfigValidator.Validate(c));
        c.Policy.HostTransferRoots.Add(@"C:\data");
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("\"*\""));
    }

    [Fact]
    public void Timeouts_OutOfRange_AreReported()
    {
        var c = Valid();
        c.Timeouts.VmStartSeconds = 0;
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("VmStartSeconds"));
    }

    [Fact]
    public void StrictHostKeyChecking_OnlyAcceptNewOrYes()
    {
        var c = Valid();
        c.Vm.StrictHostKeyChecking = "no";
        Assert.Contains(ConfigValidator.Validate(c), e => e.Contains("StrictHostKeyChecking"));
        c.Vm.StrictHostKeyChecking = "yes";
        Assert.Empty(ConfigValidator.Validate(c));
    }
}
