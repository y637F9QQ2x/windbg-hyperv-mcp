using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Server;
using ModelContextProtocol.Utils.Json;
using WinDbgMCP.Server;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Guest;
using WinDbgMCP.Server.HyperV;
using WinDbgMCP.Server.KernelDebug;
using WinDbgMCP.Server.State;
using WinDbgMCP.Server.Tools;
using WinDbgMCP.Server.UserModeDebug;
using Xunit.Abstractions;

namespace WinDbgMCP.Tests;

/// <summary>
/// Measures what the client receives and keeps the README table honest. Every registered tool is built with
/// ToolCatalog.CreateTool, the path Program.cs registers, and its protocol definition (name, description,
/// input schema, annotations) is serialized as compact JSON with the SDK's options, except that characters
/// such as the apostrophe are not escaped (the SDK sends each one as a six-character escape sequence, which a
/// client decodes back to one character). The size is the number of characters (UTF-16 code units); "about
/// tokens" in the README is that divided by 4, an estimate. The services are registered with factories that
/// are never called: the SDK only asks whether a parameter type is a service, so those parameters stay out of
/// the input schema exactly as in the running server.
/// </summary>
public class ToolListSizeTests
{
    // The numbers published in README.md, "Tool count and context cost". Change both together.
    private const int DefaultTools = 15, DefaultChars = 7_096;
    private const int NoKdTools = 8, NoKdChars = 4_044;
    private const int AllTools = 18, AllChars = 10_456;
    private const int InstructionsChars = 2_115;

    private readonly ITestOutputHelper _out;

    public ToolListSizeTests(ITestOutputHelper output) => _out = output;

    internal static IServiceProvider Services()
    {
        var s = new ServiceCollection();
        static T Never<T>(IServiceProvider _) => throw new InvalidOperationException("not constructed in this test");
        s.AddSingleton(new ServerConfig());
        s.AddSingleton(Never<StateCoordinator>);
        s.AddSingleton(Never<LabHost>);
        s.AddSingleton(Never<DbgEngManager>);
        s.AddSingleton(Never<GuestExecManager>);
        s.AddSingleton(Never<FridaManager>);
        s.AddSingleton(Never<DbgsrvManager>);
        s.AddSingleton(Never<TtdManager>);
        s.AddSingleton(Never<ToolOutput>);
        return s.BuildServiceProvider();
    }

    private static readonly JsonSerializerOptions Unescaped = new(McpJsonUtilities.DefaultOptions)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    internal static (int Count, int Chars, string Json) Measure(IEnumerable<Type> types)
    {
        var sp = Services();
        var tools = ToolCatalog.ToolMethods(types).Select(m => ToolCatalog.CreateTool(m, sp).ProtocolTool).ToList();
        var json = JsonSerializer.Serialize(tools, Unescaped);
        return (tools.Count, json.Length, json);
    }

    /// <summary>The configuration the published numbers use (the instructions text depends on these values).</summary>
    internal static ServerConfig MeasuredConfig() => new()
    {
        Vm = new VmConfig { VmName = "Test VM", GuestIpAddress = "192.0.2.10", GuestUsername = "labadmin", Lab = "lab1" },
    };

    [Fact]
    public void ServiceParameters_StayOutOfTheInputSchema()
    {
        var sp = Services();
        var method = typeof(GuestTools).GetMethod(nameof(GuestTools.GuestRunCommand))!;
        var tool = ToolCatalog.CreateTool(method, sp).ProtocolTool;
        var schema = tool.InputSchema.GetRawText();
        Assert.Contains("\"command\"", schema);
        Assert.DoesNotContain("state", schema, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"output\"", schema);
        Assert.DoesNotContain("guest\"", schema);
    }

    [Fact]
    public void EnumParameters_ListTheirValuesInTheSchema()
    {
        var sp = Services();
        var method = typeof(FridaTools).GetMethod(nameof(FridaTools.UmdFrida))!;
        var schema = ToolCatalog.CreateTool(method, sp).ProtocolTool.InputSchema.GetRawText();
        _out.WriteLine(schema);
        foreach (var v in new[] { "eval", "inject", "inject_bg", "collect_bg", "stop_bg", "list", "start_server", "help" })
            Assert.Contains($"\"{v}\"", schema);
    }

    [Fact]
    public void InputSchemas_DoNotRepeatTheNameOrTheDescription()
    {
        var sp = Services();
        foreach (var method in ToolCatalog.ToolMethods(ToolCatalog.All))
        {
            var tool = ToolCatalog.CreateTool(method, sp).ProtocolTool;
            Assert.False(tool.InputSchema.TryGetProperty("title", out _), $"{tool.Name}: title in the input schema");
            Assert.False(tool.InputSchema.TryGetProperty("description", out _), $"{tool.Name}: description in the input schema");
            Assert.Equal("object", tool.InputSchema.GetProperty("type").GetString());
            Assert.False(string.IsNullOrWhiteSpace(tool.Description));
        }
    }

    [Fact]
    public void EnumArguments_AreSnakeCaseStringsOnly()
    {
        Assert.Equal(FridaAction.InjectBg, JsonSerializer.Deserialize<FridaAction>("\"inject_bg\"", ToolJson.Options));
        Assert.Equal(TtdAction.RecordLaunch, JsonSerializer.Deserialize<TtdAction>("\"record_launch\"", ToolJson.Options));
        Assert.Equal("\"start_server\"", JsonSerializer.Serialize(DbgsrvAction.StartServer, ToolJson.Options));
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<FridaAction>("2", ToolJson.Options));
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<FridaAction>("\"attach\"", ToolJson.Options));
    }

    [Fact]
    public void ToolListSizes_MatchTheReadme()
    {
        var c = MeasuredConfig();
        var defaults = Measure(ToolCatalog.Select(c, KernelDebugPolicy.Attended));
        var noKd = Measure(ToolCatalog.Select(c, KernelDebugPolicy.Disabled));
        var all = Measure(ToolCatalog.All);
        var instructions = ServerInstructions.Build(c).Length;

        _out.WriteLine($"default tools: {defaults.Count} tools, {defaults.Chars} characters");
        _out.WriteLine($"kernel debugging disabled: {noKd.Count} tools, {noKd.Chars} characters");
        _out.WriteLine($"every tool enabled: {all.Count} tools, {all.Chars} characters");
        _out.WriteLine($"server instructions (measured config): {instructions} characters");
        _out.WriteLine(all.Json);

        Assert.Equal(DefaultTools, defaults.Count);
        Assert.Equal(NoKdTools, noKd.Count);
        Assert.Equal(AllTools, all.Count);
        Assert.Equal(DefaultChars, defaults.Chars);
        Assert.Equal(NoKdChars, noKd.Chars);
        Assert.Equal(AllChars, all.Chars);
        Assert.Equal(InstructionsChars, instructions);
    }
}
