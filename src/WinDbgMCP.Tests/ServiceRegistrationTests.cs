using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;
using WinDbgMCP.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.State;
using WinDbgMCP.Server.Tools;

namespace WinDbgMCP.Tests;

/// <summary>
/// Builds the same services Program.cs registers and resolves every service a tool asks for. Building them
/// starts the (idle) DbgEng work thread and checks a few file paths; it opens no connection, loads no
/// dbgeng.dll, starts no process and runs no task.
/// </summary>
public class ServiceRegistrationTests
{
    private static ServerConfig Config() => new()
    {
        Vm = new VmConfig { VmName = "Test VM", GuestIpAddress = "192.0.2.10", GuestUsername = "labadmin", Lab = "lab1" },
    };

    [Fact]
    public void EveryToolParameterService_IsRegisteredAndResolves()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddServerServices(Config());
        using var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });

        var isService = sp.GetRequiredService<IServiceProviderIsService>();
        var parameterTypes = ToolCatalog.All
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Where(m => m.GetCustomAttribute<McpServerToolAttribute>() != null)
            .SelectMany(m => m.GetParameters())
            .Select(p => p.ParameterType)
            .Where(t => t.IsClass && t != typeof(string))
            .Distinct()
            .ToList();

        Assert.NotEmpty(parameterTypes);
        foreach (var type in parameterTypes)
        {
            Assert.True(isService.IsService(type), $"{type.Name} is used by a tool but not registered");
            Assert.NotNull(sp.GetRequiredService(type));
        }

        // The coordinator is wired to the managers (a fresh server has no Frida background session).
        var coordinator = sp.GetRequiredService<StateCoordinator>();
        Assert.NotNull(coordinator.GetFridaBackgroundTarget);
        Assert.Null(coordinator.GetFridaBackgroundTarget!());
        Assert.NotNull(coordinator.ProbeGuestSshAsync);
        Assert.NotNull(coordinator.CleanupKdSessionAsync);
    }

    [Fact]
    public void TheSdk_ServesTheToolsProgramRegisters()
    {
        // The same registration as Program.cs, without the stdio transport (nothing is started).
        var services = new ServiceCollection();
        services.AddLogging();
        var config = Config();
        services.AddServerServices(config);
        services.AddMcpServer(o => o.ServerInfo = new() { Name = "test", Version = "0" });
        services.AddTools(ToolCatalog.Select(config, KernelDebugPolicy.Attended));
        using var sp = services.BuildServiceProvider();

        var options = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<McpServerOptions>>().Value;
        var tools = options.Capabilities?.Tools?.ToolCollection;
        Assert.NotNull(tools);
        Assert.Equal(15, tools!.Count);
        Assert.Contains(tools, t => t.ProtocolTool.Name == "kd_wait_for_event");
        Assert.All(tools, t => Assert.False(t.ProtocolTool.InputSchema.TryGetProperty("title", out _)));
    }
}
