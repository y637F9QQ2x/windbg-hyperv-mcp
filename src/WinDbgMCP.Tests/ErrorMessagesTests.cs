using WinDbgMCP.Server.State;

namespace WinDbgMCP.Tests;

public class ErrorMessagesTests
{
    [Fact]
    public void BsodCannotResume_IncludesBugcheckCodeAndRecovery()
    {
        var msg = ErrorMessages.BsodCannotResume("0x0000007E");
        Assert.Contains("0x0000007E", msg);
        Assert.Contains("!analyze -v", msg);
        // This server has no checkpoint tools, so recovery is vm_stop then vm_start and a restore is never suggested.
        Assert.Contains("vm_stop", msg);
        Assert.DoesNotContain("snapshot", msg);
    }

    [Fact]
    public void BugcheckMessages_HandleAnUnknownCode()
    {
        Assert.Contains("code unknown", ErrorMessages.BsodCannotResume(null));
        Assert.Contains("code unknown", ErrorMessages.BsodGuestOpsUnavailable(null));
        Assert.Contains("code unknown", ErrorMessages.BsodCannotBreak(null));
    }

    [Fact]
    public void ErrorMessages_ContainActionableGuidance()
    {
        // Every error message tells the model what to do next.
        Assert.Contains("vm_start", ErrorMessages.VmIsOff);
        Assert.Contains("vm_resume", ErrorMessages.VmIsPaused);
        Assert.Contains("kd_connect", ErrorMessages.KdNotConnected);
        Assert.Contains("kd_disconnect", ErrorMessages.KdAlreadyConnected);
        Assert.Contains("kd_continue", ErrorMessages.GuestFrozenByKd);
        Assert.Contains("get_system_state", ErrorMessages.GuestSshNotAnswering);
    }

    [Fact]
    public void ErrorMessages_UseNoUnmeasuredWaitTimes()
    {
        // Advice to "wait N seconds" would be a number nobody measured.
        foreach (var m in new[] { ErrorMessages.VmIsOff, ErrorMessages.GuestFrozenByKd, ErrorMessages.GuestSshNotAnswering })
            Assert.DoesNotMatch(@"\d+\s*-\s*\d+\s*seconds", m);
    }
}
