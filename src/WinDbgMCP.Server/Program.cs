using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinDbgMCP.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Tools;

// Every program this server starts is given by its full path (Processes/ToolPaths.cs). This variable also
// makes Windows leave the current directory out of any executable search by this process and its children.
Environment.SetEnvironmentVariable("NoDefaultCurrentDirectoryInExePath", "1");

// Configuration: the file named by WINDBG_HYPERV_MCP_CONFIG, else appsettings.json next to the executable.
// Environment variables with the prefix WINDBG_HYPERV_MCP_ override single values
// (for example WINDBG_HYPERV_MCP_Vm__GuestIpAddress). Nothing is read from the current directory.
var configPath = Environment.GetEnvironmentVariable("WINDBG_HYPERV_MCP_CONFIG");
if (string.IsNullOrWhiteSpace(configPath))
    configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

if (!File.Exists(configPath))
{
    Console.Error.WriteLine(
        $"windbg-hyperv-mcp: configuration file not found: {configPath}. Copy appsettings.example.json to a file " +
        "outside the repository (for example %USERPROFILE%\\windbg-hyperv-mcp.json), edit it, and set " +
        "WINDBG_HYPERV_MCP_CONFIG to its path.");
    return 2;
}

var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});
builder.Configuration
    .AddJsonFile(configPath, optional: false, reloadOnChange: false)
    .AddEnvironmentVariables("WINDBG_HYPERV_MCP_");

// stdout carries the MCP JSON-RPC stream, so every log line goes to stderr.
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);

var config = new ServerConfig();
builder.Configuration.Bind(config);

var errors = ConfigValidator.Validate(config);
if (errors.Count > 0)
{
    Console.Error.WriteLine($"windbg-hyperv-mcp: invalid configuration in {configPath}:");
    foreach (var e in errors)
        Console.Error.WriteLine("  - " + e);
    return 2;
}

var kdPolicy = ConfigValidator.ParseKernelDebugPolicy(config.Policy.KernelDebug);

builder.Services.AddServerServices(config);

var version = typeof(ServerConfig).Assembly
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

builder.Services
    .AddMcpServer(options =>
    {
        options.ServerInfo = new() { Name = "windbg-hyperv-mcp", Version = version.Split('+')[0] };
        options.ServerInstructions = ServerInstructions.Build(config);
    })
    .WithStdioServerTransport();

// The tools of the enabled groups, built by ToolCatalog.CreateTool (see there).
builder.Services.AddTools(ToolCatalog.Select(config, kdPolicy));

await builder.Build().RunAsync();
return 0;
