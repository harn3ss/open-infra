// The invocation's log tail (#407): Invoke with LogType Tail answers the last 4 KB of what that invocation
// printed, between Lambda's START, END and REPORT lines, in X-Amz-Log-Result. Whatever is written to
// Console.Out or Console.Error in the invocation's own async flow is kept for it (an AsyncLocal), so
// concurrent invocations never share output; everything still reaches the process's own streams.
using System.Diagnostics;
using System.Globalization;
using System.Text;

public class LogCapture
{
    const int TailBytes = 4096;
    public static readonly AsyncLocal<LogCapture> Current = new AsyncLocal<LogCapture>();

    readonly StringBuilder _out = new StringBuilder();
    readonly Stopwatch _clock = Stopwatch.StartNew();
    readonly object _lock = new object();

    public void Add(string s)
    {
        lock (_lock)
        {
            _out.Append(s);
            // Keep at least the last TailBytes characters (each is at least one byte of UTF-8).
            if (_out.Length > 2 * TailBytes) _out.Remove(0, _out.Length - TailBytes);
        }
    }

    // Tail is X-Amz-Log-Result: base64 of the last 4 KB of START, the output, END and REPORT.
    public string Tail(string requestId, string version, int memoryMb)
    {
        var ms = _clock.Elapsed.TotalMilliseconds;
        string output;
        lock (_lock) output = _out.ToString();
        if (output.Length > 0 && !output.EndsWith("\n")) output += "\n";
        long used = (Process.GetCurrentProcess().PeakWorkingSet64 + 1048575) / 1048576;
        var inv = CultureInfo.InvariantCulture;
        var log = $"START RequestId: {requestId} Version: {version}\n{output}END RequestId: {requestId}\n" +
            $"REPORT RequestId: {requestId}\tDuration: {ms.ToString("F2", inv)} ms\tBilled Duration: {Math.Ceiling(ms).ToString(inv)} ms\t" +
            $"Memory Size: {memoryMb} MB\tMax Memory Used: {used} MB\t\n";
        var b = Encoding.UTF8.GetBytes(log);
        int from = Math.Max(0, b.Length - TailBytes);
        return Convert.ToBase64String(b, from, b.Length - from);
    }
}

// A TextWriter that also gives the current invocation's capture what is written through it.
public class TeeWriter : TextWriter
{
    readonly TextWriter _inner;

    public TeeWriter(TextWriter inner) { _inner = inner; }

    public override Encoding Encoding => _inner.Encoding;

    public override void Write(char value)
    {
        LogCapture.Current.Value?.Add(value.ToString());
        _inner.Write(value);
    }

    public override void Write(string value)
    {
        if (value != null) LogCapture.Current.Value?.Add(value);
        _inner.Write(value);
    }

    public override void Write(char[] buffer, int index, int count)
    {
        LogCapture.Current.Value?.Add(new string(buffer, index, count));
        _inner.Write(buffer, index, count);
    }

    public override void Flush() => _inner.Flush();
}
