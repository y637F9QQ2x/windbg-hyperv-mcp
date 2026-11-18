using System.Text;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol.Types;
using WinDbgMCP.Server.Configuration;
using WinDbgMCP.Server.Security;

namespace WinDbgMCP.Server.Tools;

/// <summary>
/// Builds every tool result. A refusal, a failed precondition and a failure are returned with isError set, so a
/// client can tell them from a success. Text longer than Limits.MaxOutputChars (UTF-16 code units, the unit
/// JavaScript strings use) is cut at a line boundary; the full text is saved to a file in the "output" folder
/// under the first host transfer root, and the result ends with a marker that gives the file and the sizes.
/// </summary>
public sealed class ToolOutput
{
    private const int MarkerReserve = 600;

    private readonly int _max;
    private readonly IReadOnlyList<string> _roots;
    private readonly ILogger<ToolOutput> _logger;

    public ToolOutput(ServerConfig config, ILogger<ToolOutput> logger)
    {
        _max = config.Limits.MaxOutputChars;
        _roots = HostPathPolicy.EffectiveRoots(config.Policy.HostTransferRoots);
        _logger = logger;
    }

    public CallToolResponse Ok(string tool, string? text) => Build(tool, text, isError: false);

    public CallToolResponse Error(string tool, string? text) => Build(tool, text, isError: true);

    private CallToolResponse Build(string tool, string? text, bool isError) => new()
    {
        IsError = isError,
        Content = new List<Content> { new() { Type = "text", Text = Bound(tool, text ?? "") } },
    };

    /// <summary><paramref name="text"/> if it fits, else its start, cut at a line boundary, and a marker.</summary>
    internal string Bound(string tool, string text)
    {
        if (text.Length <= _max) return text;

        var keep = CutPoint(text, _max - MarkerReserve);
        var saved = SaveFull(tool, text);
        return text[..keep].TrimEnd() +
               $"\n\n[windbg-hyperv-mcp: the result was cut after {keep:N0} of {text.Length:N0} characters " +
               $"(Limits.MaxOutputChars is {_max:N0}). {saved} Ask for less output, for example a narrower command.]";
    }

    /// <summary>The last line break before <paramref name="limit"/>, unless that is in the first half.</summary>
    internal static int CutPoint(string text, int limit)
    {
        if (limit <= 0) return 0;
        var nl = text.LastIndexOf('\n', Math.Min(limit, text.Length) - 1);
        return nl > limit / 2 ? nl : limit;
    }

    private string SaveFull(string tool, string text)
    {
        try
        {
            var dir = HostPathPolicy.OutputDirectory(_roots);
            var name = $"{tool}-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8]}.txt";
            var refusal = HostPathPolicy.Check(Path.Combine(dir, name), _roots[0] == HostPathPolicy.Unrestricted
                ? new[] { HostPathPolicy.Unrestricted } : _roots, out var full);
            if (refusal != null)
                return "The full text was not saved: " + refusal;
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text, new UTF8Encoding(false));
            return $"The full text is in {HostPathPolicy.ForDisplay(full)} on the host.";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save the full {Tool} result", tool);
            return $"The full text was not saved ({ex.GetType().Name}: {ex.Message}).";
        }
    }
}
