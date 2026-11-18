using WinDbgMCP.Server.State;

namespace WinDbgMCP.Tests;

public class SystemStateTests
{
    [Fact]
    public void DefaultState_HasSafeDefaults()
    {
        // A fresh server knows nothing yet: no guest operation is allowed until the first probe answers.
        var state = new SystemState();
        Assert.Equal(VmPowerState.Unknown, state.VmPower);
        Assert.False(state.VmPowerFromHost);
        Assert.Equal(GuestSshState.Unknown, state.GuestSsh);
        Assert.False(state.KdConnected);
        Assert.Equal(DebugExecutionStatus.Uninitialized, state.KdExecStatus);
        Assert.False(state.IsBugcheck);
        Assert.Null(state.BugcheckCode);
        Assert.False(state.GuestOpsAvailable);
        Assert.Null(state.FridaBackgroundTarget);
    }
}
