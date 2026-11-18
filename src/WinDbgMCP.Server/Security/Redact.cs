using System.Text.RegularExpressions;

namespace WinDbgMCP.Server.Security;

/// <summary>Removes secrets from strings that are written to logs.</summary>
public static class Redact
{
    private static readonly Regex SecretField = new(
        @"(?<name>\b(?:key|password|pw)\s*=\s*)(?<value>[^,;\s]*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex TokenOption = new(
        @"(?<name>--token[\s=]+)(?<value>[^\s'""]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>A DbgEng connection string with the value of every key= / password= field replaced.</summary>
    public static string ConnectionString(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : SecretField.Replace(value, m => m.Groups["name"].Value + "<redacted>");

    /// <summary>A command line or argument with key=, password= and --token values replaced.</summary>
    public static string CommandLine(string? value) =>
        string.IsNullOrEmpty(value)
            ? string.Empty
            : TokenOption.Replace(ConnectionString(value), m => m.Groups["name"].Value + "<redacted>");

    /// <summary>An argument list for a log line, with secret values replaced.</summary>
    public static string Arguments(IEnumerable<string> args) => CommandLine(string.Join(" ", args));
}
