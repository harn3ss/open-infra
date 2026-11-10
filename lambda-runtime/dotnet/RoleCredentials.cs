// The execution role's credentials, as Lambda hands them to a function: AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN are in the environment before the handler assembly loads, so
// code that reads credentials as it loads (a constructor, a static initializer) finds them. They are the role's
// session from sts:AssumeRoleWithWebIdentity on AWS_ENDPOINT_URL_STS, with the function's own identity token
// (AWS_WEB_IDENTITY_TOKEN_FILE). The AWS SDK for .NET reads them from the environment at every call, so a
// refresh reaches a client made at load; AWS_CREDENTIAL_EXPIRATION carries their expiry for the other SDKs and
// tools a handler may run, which read it to know when to read them again. Fetched at cold start when AWS_ROLE_ARN,
// AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ENDPOINT_URL_STS are set and AWS_ACCESS_KEY_ID is not; refreshed before
// an invocation when they would expire within 5 minutes of its Timeout's end, and no call is made otherwise.
// Never logged; a failure never fails the function: at cold start nothing is set (the SDK's web identity
// provider still works), at a refresh the current credentials are kept and the next try waits 30 seconds.
using System.Diagnostics;
using System.Globalization;
using System.Xml;
using System.Xml.Linq;

static class RoleCredentials
{
    const string DurationSeconds = "43200"; // asked for first; a role whose maximum is shorter gets its maximum
    static readonly TimeSpan StsTimeout = TimeSpan.FromSeconds(5); // one STS call, connect to answer
    static readonly TimeSpan Early = TimeSpan.FromMinutes(5); // refreshed when they would expire this soon after an invocation's deadline
    static readonly TimeSpan RetryAfterFailure = TimeSpan.FromSeconds(30);

    // No proxy (the web identity token goes to the STS endpoint and nowhere else) and no redirects.
    static readonly HttpClient Client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = StsTimeout })
    {
        Timeout = Timeout.InfiniteTimeSpan, // each call carries its own deadline
        MaxResponseContentBufferSize = 1 << 20,
    };
    static readonly SemaphoreSlim Gate = new SemaphoreSlim(1, 1);
    static volatile bool _active; // set by this runtime: only then refreshed
    static long _nextTry; // the Stopwatch timestamp at which a refresh is due

    sealed record Creds(string AccessKeyId, string SecretAccessKey, string SessionToken, string Expiration, DateTimeOffset Expires);

    static string Env(string name) => Environment.GetEnvironmentVariable(name) ?? "";

    // InitAsync runs at cold start, before the handler assembly loads. It never throws.
    public static async Task InitAsync()
    {
        if (Env("AWS_ROLE_ARN") == "" || Env("AWS_WEB_IDENTITY_TOKEN_FILE") == "" || Env("AWS_ENDPOINT_URL_STS") == "") return;
        if (Env("AWS_ACCESS_KEY_ID") != "") return; // keys already given: they stay the function's
        Creds c;
        try { c = await AssumeAsync(); }
        catch (Exception e)
        {
            Console.Error.WriteLine($"open-infra-runtime: the execution role's credentials are not in the environment: {e.Message}; " +
                "the AWS SDK gets them with the web identity token instead");
            return;
        }
        Set(c);
        Console.Error.WriteLine($"open-infra-runtime: the execution role's credentials are in the environment (expiring {c.Expiration})");
    }

    // RefreshIfDueAsync runs before each invocation: completed at once, with no call at all, until the
    // credentials near their expiry. Concurrent invocations wait for the one refresh. It never throws.
    public static Task RefreshIfDueAsync() =>
        !_active || Stopwatch.GetTimestamp() < Interlocked.Read(ref _nextTry) ? Task.CompletedTask : RefreshAsync();

    static async Task RefreshAsync()
    {
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (Stopwatch.GetTimestamp() < Interlocked.Read(ref _nextTry)) return; // refreshed (or failed) while this one waited
            Creds c;
            try { c = await AssumeAsync().ConfigureAwait(false); }
            catch (Exception e)
            {
                Interlocked.Exchange(ref _nextTry, Stopwatch.GetTimestamp() + (long)(RetryAfterFailure.TotalSeconds * Stopwatch.Frequency));
                Console.Error.WriteLine($"open-infra-runtime: could not refresh the execution role's credentials: {e.Message}; the current ones are kept");
                return;
            }
            Set(c);
            Console.Error.WriteLine($"open-infra-runtime: refreshed the execution role's credentials (expiring {c.Expiration})");
        }
        finally { Gate.Release(); }
    }

    // Set puts the credentials in the environment, and when the next refresh is due: their lifetime (by the
    // wall clock, as STS states it) is counted down on the monotonic clock.
    static void Set(Creds c)
    {
        Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", c.AccessKeyId);
        Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", c.SecretAccessKey);
        Environment.SetEnvironmentVariable("AWS_SESSION_TOKEN", c.SessionToken);
        Environment.SetEnvironmentVariable("AWS_CREDENTIAL_EXPIRATION", c.Expiration);
        var due = c.Expires - DateTimeOffset.UtcNow - Early - TimeSpan.FromSeconds(Bootstrap.TimeoutSeconds);
        Interlocked.Exchange(ref _nextTry, Stopwatch.GetTimestamp() + (long)(due.TotalSeconds * Stopwatch.Frequency));
        _active = true;
    }

    // AssumeAsync is sts:AssumeRoleWithWebIdentity for the execution role. An exception's message holds no
    // credential and no token.
    static async Task<Creds> AssumeAsync()
    {
        var tokenFile = Env("AWS_WEB_IDENTITY_TOKEN_FILE");
        string token;
        try { token = File.ReadAllText(tokenFile).Trim(); }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"cannot read AWS_WEB_IDENTITY_TOKEN_FILE {tokenFile}: {e.Message}");
        }
        if (token.Length == 0) throw new InvalidOperationException($"AWS_WEB_IDENTITY_TOKEN_FILE {tokenFile} is empty");
        var session = Env("AWS_ROLE_SESSION_NAME");
        if (session == "") session = Env("AWS_LAMBDA_FUNCTION_NAME");
        if (session == "") session = "lambda";
        var form = new List<KeyValuePair<string, string>>
        {
            new("Action", "AssumeRoleWithWebIdentity"), new("Version", "2011-06-15"), new("RoleArn", Env("AWS_ROLE_ARN")),
            new("RoleSessionName", session), new("WebIdentityToken", token), new("DurationSeconds", DurationSeconds),
        };
        var endpoint = Env("AWS_ENDPOINT_URL_STS").TrimEnd('/') + "/";
        var (status, body) = await PostAsync(endpoint, form).ConfigureAwait(false);
        if ((status < 200 || status >= 300) && (body.Contains("DurationSeconds") || body.Contains("MaxSessionDuration")))
        {
            form.RemoveAt(form.Count - 1); // the role's own maximum session instead
            (status, body) = await PostAsync(endpoint, form).ConfigureAwait(false);
        }
        XDocument doc = null;
        try { doc = XDocument.Parse(body); }
        catch (XmlException) { /* not XML: no fields */ }
        static string Text(XContainer root, string name) =>
            root?.Descendants().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim() ?? "";
        if (status < 200 || status >= 300)
        {
            var code = Text(doc, "Code");
            var msg = Text(doc, "Message").Replace(token, "<token>");
            if (msg.Length > 200) msg = msg[..200];
            throw new InvalidOperationException($"STS answered HTTP {status}" + (code != "" ? " " + code : "") + (msg != "" ? ": " + msg : ""));
        }
        var creds = doc?.Descendants().FirstOrDefault(e => e.Name.LocalName == "Credentials");
        var c = new Creds(Text(creds, "AccessKeyId"), Text(creds, "SecretAccessKey"), Text(creds, "SessionToken"), Text(creds, "Expiration"), default);
        if (c.AccessKeyId == "" || c.SecretAccessKey == "" || c.SessionToken == "" ||
            !DateTimeOffset.TryParse(c.Expiration, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var expires))
            throw new InvalidOperationException("STS's answer has no AccessKeyId, SecretAccessKey, SessionToken and Expiration");
        return c with { Expires = expires };
    }

    // PostAsync POSTs the form to the STS endpoint: (status, body). Throws for a network failure or no answer
    // in StsTimeout.
    static async Task<(int, string)> PostAsync(string endpoint, List<KeyValuePair<string, string>> form)
    {
        using var cts = new CancellationTokenSource(StsTimeout);
        try
        {
            using var content = new FormUrlEncodedContent(form);
            using var resp = await Client.PostAsync(endpoint, content, cts.Token).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ((int)resp.StatusCode, body);
        }
        catch (OperationCanceledException)
        {
            throw new InvalidOperationException($"no answer from {new Uri(endpoint).Authority} in {StsTimeout.TotalSeconds}s");
        }
        catch (HttpRequestException e)
        {
            throw new InvalidOperationException(e.Message);
        }
    }
}
