using WinDbgMCP.Server.KernelDebug.Interop;

namespace WinDbgMCP.Tests;

public class CheckCommandTests
{
    [Theory]
    [InlineData("g")]
    [InlineData("gc")]
    [InlineData("gh")]
    [InlineData("gn")]
    [InlineData("gu")]
    [InlineData("gN")]
    [InlineData("t")]
    [InlineData("p")]
    [InlineData("ta")]
    [InlineData("pa")]
    [InlineData("tc")]
    [InlineData("pc")]
    [InlineData("tt")]
    [InlineData("pt")]
    [InlineData("th")]
    [InlineData("ph")]
    [InlineData("tb")]
    [InlineData("tct")]
    [InlineData("pct")]
    [InlineData("wt")]
    [InlineData("q")]
    [InlineData("qq")]
    [InlineData("qd")]
    [InlineData(".detach")]
    [InlineData(".restart")]
    [InlineData(".reboot")]
    public void BlockedCommands_AreDetected(string cmd)
    {
        var (isBlocked, blockedCmd, suggestion) = DbgEngConstants.CheckCommand(cmd);
        Assert.True(isBlocked, $"'{cmd}' should be blocked");
        Assert.Equal(cmd, blockedCmd);
        Assert.NotEmpty(suggestion);
    }

    [Theory]
    [InlineData("k")]
    [InlineData("r")]
    [InlineData("lm")]
    [InlineData("db 0x12345")]
    [InlineData("!process 0 0")]
    [InlineData("!analyze -v")]
    [InlineData("bp nt!NtCreateFile")]
    [InlineData("bp nt!NtCreateFile \"r rcx; gc\"")]   // the engine runs the quoted command at the hit
    [InlineData("u rip")]
    [InlineData(".reload /f")]
    [InlineData("x nt!NtCreate*")]
    [InlineData("dv")]
    [InlineData("dd rsp L10")]
    [InlineData("dt nt!_EPROCESS")]
    public void SafeCommands_AreAllowed(string cmd)
    {
        var (isBlocked, _, _) = DbgEngConstants.CheckCommand(cmd);
        Assert.False(isBlocked, $"'{cmd}' should be allowed");
    }

    [Fact]
    public void CompoundCommand_BlocksIfAnyPartBlocked()
    {
        var (isBlocked, blockedCmd, _) = DbgEngConstants.CheckCommand("bp nt!NtCreateFile; g");
        Assert.True(isBlocked);
        Assert.Equal("g", blockedCmd);
    }

    [Fact]
    public void CompoundCommand_AllowsIfAllSafe()
    {
        var (isBlocked, _, _) = DbgEngConstants.CheckCommand("bp nt!NtCreateFile; k; r");
        Assert.False(isBlocked);
    }

    [Theory]
    [InlineData("g @$ra")]
    [InlineData("g\t@$ra")]   // any whitespace separates the arguments
    [InlineData("g@$ra")]     // no whitespace at all
    [InlineData("  g")]
    public void BlockedCommand_WithArgs_StillBlocked(string cmd)
    {
        var (isBlocked, blockedCmd, _) = DbgEngConstants.CheckCommand(cmd);
        Assert.True(isBlocked);
        Assert.Equal("g", blockedCmd);
    }

    [Theory]
    [InlineData("G", "kd_continue")]
    [InlineData("T", "kd_step")]
    [InlineData("P", "kd_step")]
    [InlineData("Q", "kd_disconnect")]
    [InlineData(".DETACH", "kd_disconnect")]
    public void BlockedCommands_AreCaseInsensitive_WithTheRightSuggestion(string cmd, string suggestionTool)
    {
        var (isBlocked, _, suggestion) = DbgEngConstants.CheckCommand(cmd);
        Assert.True(isBlocked, $"'{cmd}' should be blocked (case-insensitive)");
        Assert.Contains(suggestionTool, suggestion);
    }

    [Fact]
    public void StepCommands_SuggestTheRightKdStepMode()
    {
        Assert.Contains("into", DbgEngConstants.CheckCommand("t").Suggestion);
        Assert.Contains("into", DbgEngConstants.CheckCommand("tct").Suggestion);
        Assert.Contains("over", DbgEngConstants.CheckCommand("p").Suggestion);
        Assert.Contains("over", DbgEngConstants.CheckCommand("pct").Suggestion);
    }

    [Fact]
    public void EmptyCommand_IsAllowed()
    {
        var (isBlocked, _, _) = DbgEngConstants.CheckCommand("");
        Assert.False(isBlocked);
    }
}
