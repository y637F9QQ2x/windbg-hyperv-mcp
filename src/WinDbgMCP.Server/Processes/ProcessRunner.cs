using System.Diagnostics;
using System.Text;

namespace WinDbgMCP.Server.Processes;

/// <summary>Result of a host child process (exit code and captured output).</summary>
public sealed class ProcessResult
{
    public int ExitCode { get; }
    public string Stdout { get; }
    public string Stderr { get; }
    public bool Success => ExitCode == 0;

    public ProcessResult(int exitCode, string stdout, string stderr)
    {
        ExitCode = exitCode;
        Stdout = stdout;
        Stderr = stderr;
    }
}

/// <summary>
/// The one way this server runs a short-lived host program (ssh.exe, scp.exe, frida.exe, frida-ps.exe,
/// cdb.exe): a fully qualified path, every argument through ProcessStartInfo.ArgumentList, standard input
/// closed, the working directory fixed to System32 (so nothing is read from the caller's current directory,
/// for example the ntsd.ini that cdb.exe would run as a script), output kept up to
/// <see cref="MaxCapturedChars"/> per stream, and the whole process tree ended on timeout or cancellation.
/// </summary>
public static class ProcessRunner
{
    public const int MaxCapturedChars = 4_000_000;

    /// <summary>Process start settings shared with the long-running Frida session.</summary>
    public static ProcessStartInfo StartInfo(string fileName, IEnumerable<string> arguments,
        IReadOnlyDictionary<string, string>? environment = null, Encoding? encoding = null)
    {
        if (!Path.IsPathFullyQualified(fileName))
            throw new ArgumentException($"'{fileName}' is not a fully qualified path.", nameof(fileName));

        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,   // never inherit the MCP stdio stream
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        if (encoding != null)
        {
            psi.StandardOutputEncoding = encoding;
            psi.StandardErrorEncoding = encoding;
        }
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        if (environment != null)
            foreach (var (k, v) in environment) psi.Environment[k] = v;
        return psi;
    }

    /// <summary>
    /// Run <paramref name="fileName"/> to completion. Throws <see cref="FileNotFoundException"/> when the program
    /// does not exist, <see cref="TimeoutException"/> when <paramref name="timeout"/> passes, and
    /// <see cref="OperationCanceledException"/> when <paramref name="ct"/> is cancelled.
    /// </summary>
    public static async Task<ProcessResult> RunAsync(string fileName, IEnumerable<string> arguments, TimeSpan timeout,
        CancellationToken ct, string label, IReadOnlyDictionary<string, string>? environment = null, Encoding? encoding = null)
    {
        var psi = StartInfo(fileName, arguments, environment, encoding);
        if (!File.Exists(fileName))
            throw new FileNotFoundException($"{Path.GetFileName(fileName)} was not found at {fileName}.", fileName);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        using var process = new Process { StartInfo = psi };
        process.Start();
        try { process.StandardInput.Close(); } catch (IOException) { }

        // The reads end when the pipes close: at exit, or when the tree is ended below.
        var stdout = ReadBoundedAsync(process.StandardOutput);
        var stderr = ReadBoundedAsync(process.StandardError);

        try
        {
            await process.WaitForExitAsync(cts.Token);
            await Task.WhenAll(stdout, stderr).WaitAsync(cts.Token);
            return new ProcessResult(process.ExitCode, stdout.Result, stderr.Result);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await process.WaitForExitAsync(exitCts.Token);
            }
            catch
            {
                // Already gone, or it did not exit in time; the pipes close with it either way.
            }
            try { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(3)); } catch { }

            if (ct.IsCancellationRequested) throw;
            throw new TimeoutException($"{label} timed out after {timeout.TotalSeconds:0} s.");
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var text = new BoundedText(MaxCapturedChars);
        var buffer = new char[8192];
        try
        {
            int n;
            while ((n = await reader.ReadAsync(buffer.AsMemory())) > 0)
                text.Append(buffer.AsSpan(0, n));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // The pipe broke because the process was ended: keep what arrived.
        }
        return text.ToString();
    }
}

/// <summary>Text that keeps its first <c>limit</c> characters and counts the rest.</summary>
public sealed class BoundedText
{
    private readonly StringBuilder _sb = new();
    private readonly int _limit;

    public BoundedText(int limit) => _limit = limit;

    public long Dropped { get; private set; }

    public void Append(ReadOnlySpan<char> s)
    {
        var room = _limit - _sb.Length;
        if (room >= s.Length) { _sb.Append(s); return; }
        if (room > 0) _sb.Append(s[..room]);
        Dropped += s.Length - Math.Max(room, 0);
    }

    public override string ToString() =>
        Dropped == 0
            ? _sb.ToString()
            : _sb + $"\n[windbg-hyperv-mcp: {Dropped:N0} more characters of output were dropped (limit {_limit:N0})]";
}
