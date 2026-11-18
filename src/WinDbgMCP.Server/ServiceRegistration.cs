using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.KernelDebug;
using WinDbgMCP.Server.State;
using WinDbgMCP.Server.Tools;
using WinDbgMCP.Server.UserModeDebug;

namespace WinDbgMCP.Server;

/// <summary>The services the tools receive by dependency injection. Separate from Program.cs so a test can build them.</summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddServerServices(this IServiceCollection services, ServerConfig config)
    {
        // One server process controls one VM, so every service is a singleton.
        services.AddSingleton(config);
        services.AddSingleton<ToolOutput>();
        services.AddSingleton<LabHost>();

        // DbgEng runs on one dedicated thread (COM thread affinity). dbgeng.dll is loaded on the first kd_connect.
        services.AddSingleton<DbgEngThread>(sp =>
            new DbgEngThread(sp.GetRequiredService<ILogger<DbgEngThread>>()));
        services.AddSingleton<DbgEngManager>();

        services.AddSingleton<GuestExecManager>();
        services.AddSingleton<FridaManager>();
        services.AddSingleton<DbgsrvManager>();
        services.AddSingleton<TtdManager>();

        services.AddSingleton<StateCoordinator>(sp =>
        {
            var lab = sp.GetRequiredService<LabHost>();
            var dbgEng = sp.GetRequiredService<DbgEngManager>();
            var frida = sp.GetRequiredService<FridaManager>();

            var coordinator = new StateCoordinator(
                sp.GetRequiredService<ServerConfig>(), sp.GetRequiredService<ILogger<StateCoordinator>>());

            coordinator.ProbeGuestSshAsync = () => lab.ProbeGuestSshAsync();

            coordinator.IsDbgEngConnected = () => dbgEng.IsConnected;
            coordinator.GetDbgEngExecutionStatus = () => dbgEng.GetExecutionStatus();
            coordinator.GetPendingEventCount = () => dbgEng.PendingEventCount;

            coordinator.GetFridaBackgroundTarget = () => frida.BackgroundTarget;

            // Repeatable resets after vm_stop.
            coordinator.CleanupKdSessionAsync = () => dbgEng.ResetConnectionStateAsync();
            coordinator.CleanupFridaSession = () => frida.ResetSession();

            return coordinator;
        });

        return services;
    }
}
