using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol.Utils.Json;

namespace WinDbgMCP.Server.Tools;

// Tool parameters with a fixed set of values are enums, so the input schema lists the values
// ("enum": [...]) and the SDK rejects any other value before the tool runs. On the wire the names are
// snake_case (InjectBg is "inject_bg"); see ToolJson.

public enum StepMode { Over, Into }

public enum FridaAction { Eval, Inject, InjectBg, CollectBg, StopBg, List, StartServer, Help }

public enum DbgsrvAction { Command, StartServer, Help }

public enum TtdAction { RecordLaunch, RecordAttach, Stop, List, Retrieve }

/// <summary>
/// The JSON options the tools are registered with: the SDK's defaults, with enums written and read as
/// snake_case strings only (no integers). Used for the input schemas and for reading tool arguments.
/// </summary>
public static class ToolJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(McpJsonUtilities.DefaultOptions);
        // First in the list, so it is chosen before the SDK's own enum converter.
        options.Converters.Insert(0, new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false));
        options.MakeReadOnly();
        return options;
    }
}
