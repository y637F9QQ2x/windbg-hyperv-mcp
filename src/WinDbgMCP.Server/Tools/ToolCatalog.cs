using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;
using WinDbgMCP.Server.Configuration;

namespace WinDbgMCP.Server.Tools;

/// <summary>
/// Which tool classes are registered, and how each tool is built. A tool that a policy turns off is not
/// registered at all, so its definition does not take space in the client's context and the model cannot
/// call it.
/// </summary>
public static class ToolCatalog
{
    public static List<Type> Select(ServerConfig config, KernelDebugPolicy kd)
    {
        var types = new List<Type> { typeof(MetaTools), typeof(VmTools), typeof(GuestTools) };

        if (kd != KernelDebugPolicy.Disabled)
            types.Add(typeof(KernelDebugTools));

        if (config.Tools.Frida) types.Add(typeof(FridaTools));
        if (config.Tools.Dbgsrv) types.Add(typeof(DbgsrvTools));
        if (config.Tools.Ttd) types.Add(typeof(TtdTools));

        return types;
    }

    /// <summary>Every tool class this server has (for tests and documentation).</summary>
    public static readonly Type[] All =
    {
        typeof(MetaTools), typeof(VmTools), typeof(KernelDebugTools), typeof(GuestTools), typeof(FridaTools), typeof(DbgsrvTools), typeof(TtdTools),
    };

    /// <summary>
    /// Register the tools of <paramref name="toolTypes"/> the way the SDK's WithTools does: one McpServerTool
    /// singleton each, built with the service provider. The SDK serves every McpServerTool registered this way.
    /// </summary>
    public static IServiceCollection AddTools(this IServiceCollection services, IEnumerable<Type> toolTypes)
    {
        foreach (var method in ToolMethods(toolTypes))
            services.AddSingleton<McpServerTool>(sp => CreateTool(method, sp));
        return services;
    }

    /// <summary>The tool methods of <paramref name="types"/>.</summary>
    public static IEnumerable<MethodInfo> ToolMethods(IEnumerable<Type> types) =>
        types.SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
             .Where(m => m.GetCustomAttribute<McpServerToolAttribute>() != null);

    /// <summary>
    /// Build one tool the way the SDK's WithTools does (parameters that <paramref name="services"/> can supply
    /// stay out of the input schema), with this server's JSON options. The SDK also copies the tool name and the
    /// whole description into the input schema as "title" and "description"; the tool already carries both, so
    /// the copies are removed and each description is sent once.
    /// </summary>
    public static McpServerTool CreateTool(MethodInfo method, IServiceProvider services)
    {
        var tool = McpServerTool.Create(method, (object?)null,
            new McpServerToolCreateOptions { Services = services, SerializerOptions = ToolJson.Options });
        tool.ProtocolTool.InputSchema = WithoutTitleAndDescription(tool.ProtocolTool.InputSchema);
        return tool;
    }

    internal static JsonElement WithoutTitleAndDescription(JsonElement schema)
    {
        if (JsonNode.Parse(schema.GetRawText()) is not JsonObject node)
            return schema;
        node.Remove("title");
        node.Remove("description");
        using var doc = JsonDocument.Parse(node.ToJsonString());
        return doc.RootElement.Clone();
    }
}
