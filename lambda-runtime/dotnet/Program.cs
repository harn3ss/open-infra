// open-infra Lambda runtime shim (.NET 8) — the "runtime interface" half of the runtime-base-image +
// handler-shim ingestion model (kind: Function spec.code). The .NET sibling of bootstrap.py /
// bootstrap.js, speaking the EXACT same env contract so the composition wires all three identically.
//
// A user ships a PUBLISHED .NET handler (a Zip of the build output: the handler assembly + its deps),
// not a container. open-infra runs it on THIS prebuilt base image: the zip is unpacked into /var/task
// (a ConfigMap mount, or this shim fetches+unzips the function's stored deployment package or the code
// bucket object at cold start), and the shim loads the handler assembly, invokes the declared method by
// reflection, and serves it over HTTP.
//
// Code sources (env): OPENINFRA_CODE_BUCKET / OPENINFRA_CODE_KEY = the handler .zip (S3/MinIO), or
// OPENINFRA_CODE_URL = the function's stored deployment package, served by the aws-shim (never both),
// fetched with the function's own identity token, no keys: OPENINFRA_CODE_SHA256 = its recorded SHA-256
// (64 lowercase hex), checked before unpacking; OPENINFRA_CODE_TOKEN_FILE = the projected identity token,
// sent as "Authorization: Bearer <token>". OPENINFRA_LAYERS = JSON [{bucket,key}] into /opt.
//
// Handler format (AWS .NET convention): OPENINFRA_HANDLER = "Assembly::Namespace.Type::Method".
// Supported signatures: Method(TIn) and Method(TIn, ILambdaContext), sync or Task/Task<T>. TIn is the
// event: a string (raw JSON), a Stream, or any type deserialized from the JSON. An ILambdaContext
// parameter is supplied via a DispatchProxy of the HANDLER'S OWN ILambdaContext type, so any
// Amazon.Lambda.Core version works without the shim referencing it. A thrown/faulted handler -> 502
// {errorType,errorMessage}, never a silent 200. GET /_openinfra_health -> 200.
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Runtime.Loader;
using Amazon.S3;
using Amazon.S3.Model;

static class Bootstrap
{
    static readonly string TaskDir = Environment.GetEnvironmentVariable("OPENINFRA_TASK_DIR") ?? "/var/task";
    static readonly string OptDir = Environment.GetEnvironmentVariable("OPENINFRA_OPT_DIR") ?? "/opt";
    static readonly int Port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var p) ? p : 8080;
    static readonly DateTime Start = DateTime.UtcNow;

    static MethodInfo _method;
    static object _target;
    static ParameterInfo[] _params;

    static async Task<int> Main()
    {
        // Every write to the console also reaches the current invocation's log tail, when it asked for one.
        Console.SetOut(new TeeWriter(Console.Out));
        Console.SetError(new TeeWriter(Console.Error));
        try
        {
            await FetchCodeAsync();
            LoadHandler();
        }
        catch (CodeSourceException e)
        {
            Console.Error.WriteLine("open-infra-runtime: " + e.Message);
            return 2;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("open-infra-runtime: startup failed:\n" + e);
            return 2;
        }
        Console.Error.WriteLine($"open-infra-runtime: serving {Environment.GetEnvironmentVariable("OPENINFRA_HANDLER")} on :{Port} " +
            $"(task dir {TaskDir}, cold-start {(DateTime.UtcNow - Start).TotalSeconds:F3}s)");
        Serve();
        return 0;
    }

    // Fetch+unzip the handler .zip (the stored deployment package, or the code bucket object) into
    // /var/task and any layers into /opt at cold start. .NET has a stdlib zip reader
    // (System.IO.Compression), so no external unzip is needed. No-op when the handler is
    // ConfigMap-mounted and no layers are declared.
    static async Task FetchCodeAsync()
    {
        var bucket = Environment.GetEnvironmentVariable("OPENINFRA_CODE_BUCKET");
        var codeUrl = Environment.GetEnvironmentVariable("OPENINFRA_CODE_URL");
        var layersRaw = Environment.GetEnvironmentVariable("OPENINFRA_LAYERS") ?? "";
        if (!string.IsNullOrEmpty(codeUrl))
        {
            if (!string.IsNullOrEmpty(bucket))
                throw new CodeSourceException("OPENINFRA_CODE_URL and OPENINFRA_CODE_BUCKET are both set: a function's deployment " +
                    "package comes from one code source (its stored package or an S3 object), not both");
            await FetchPackageAsync(codeUrl, TaskDir);
        }
        if (string.IsNullOrEmpty(bucket) && string.IsNullOrEmpty(layersRaw)) return;

        var cfg = new AmazonS3Config { ForcePathStyle = true };
        // Service-scoped AWS_ENDPOINT_URL_S3 first (so the handler's global endpoint isn't forced to the
        // S3 gateway); fall back to the legacy global AWS_ENDPOINT_URL.
        var endpoint = Environment.GetEnvironmentVariable("AWS_ENDPOINT_URL_S3") ?? Environment.GetEnvironmentVariable("AWS_ENDPOINT_URL");
        if (!string.IsNullOrEmpty(endpoint)) cfg.ServiceURL = endpoint;
        else cfg.RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(
            Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1");
        using var s3 = new AmazonS3Client(cfg);

        if (!string.IsNullOrEmpty(bucket))
            await FetchUnzipAsync(s3, bucket, Environment.GetEnvironmentVariable("OPENINFRA_CODE_KEY") ?? "", TaskDir);
        if (!string.IsNullOrEmpty(layersRaw))
            foreach (var layer in JsonSerializer.Deserialize<List<Layer>>(layersRaw))
                await FetchUnzipAsync(s3, layer.bucket, layer.key ?? "", OptDir);
    }

    sealed class Layer { public string bucket { get; set; } public string key { get; set; } }

    static async Task FetchUnzipAsync(AmazonS3Client s3, string bucket, string key, string dest)
    {
        using var resp = await s3.GetObjectAsync(new GetObjectRequest { BucketName = bucket, Key = key });
        using var ms = new MemoryStream();
        await resp.ResponseStream.CopyToAsync(ms);
        ms.Position = 0;
        // Capture the length BEFORE constructing the ZipArchive: its using-block disposes `ms`
        // (ZipArchive defaults to leaveOpen:false), so reading ms.Length after it throws
        // ObjectDisposedException ("Cannot access a closed Stream") — which crashed the bootstrap
        // of every dotnet function before a byte of the package was unpacked.
        long size = ms.Length;
        Directory.CreateDirectory(dest);
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
            zip.ExtractToDirectory(dest, overwriteFiles: true);
        Console.Error.WriteLine($"open-infra-runtime: unpacked s3://{bucket}/{key} ({size} bytes) into {dest}");
    }

    // --- Stored deployment package (OPENINFRA_CODE_URL): Lambda's own model, where the platform keeps the
    // function's .zip and the function fetches it with its OWN identity — no keys in the pod. The aws-shim
    // serves a pod only its own function's package; the shim may be restarting, so a network error, a 5xx
    // or a 429 is retried (5 attempts, 1s/2s/4s/8s apart), while a refusal (400/401/403/404, any other
    // status) fails start at once. The token is re-read on every attempt (kubelet rotates it), never logged.
    const long CodeMaxBytes = 64L * 1024 * 1024;
    const int CodeAttempts = 5;
    static readonly TimeSpan CodeAttemptTimeout = TimeSpan.FromMinutes(2); // a stalled attempt is retried

    // A start failure whose message says it all: logged alone, without a stack trace.
    sealed class CodeSourceException : Exception { public CodeSourceException(string message) : base(message) { } }
    // A network failure, a 5xx or a 429 from the code URL: worth another attempt.
    sealed class RetryableFetchException : Exception { public RetryableFetchException(string message) : base(message) { } }

    static string ReadToken(string tokenFile)
    {
        string token;
        try { token = File.ReadAllText(tokenFile).Trim(); }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
        {
            throw new CodeSourceException($"cannot read OPENINFRA_CODE_TOKEN_FILE {tokenFile}: {e.Message}");
        }
        if (token.Length == 0)
            throw new CodeSourceException($"OPENINFRA_CODE_TOKEN_FILE {tokenFile} is empty: the function's identity token is missing");
        return token;
    }

    static async Task FetchPackageAsync(string codeUrl, string dest)
    {
        if (!Uri.TryCreate(codeUrl, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new CodeSourceException($"OPENINFRA_CODE_URL must be an http or https URL, got '{codeUrl}'");
        var want = Environment.GetEnvironmentVariable("OPENINFRA_CODE_SHA256") ?? "";
        if (want.Length != 64 || !want.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            throw new CodeSourceException("OPENINFRA_CODE_URL needs OPENINFRA_CODE_SHA256, the deployment package's recorded SHA-256 " +
                "as 64 lowercase hex characters" + (want != "" ? $"; got '{want}'" : "; it is not set"));
        var tokenFile = Environment.GetEnvironmentVariable("OPENINFRA_CODE_TOKEN_FILE") ?? "";
        if (tokenFile == "")
            throw new CodeSourceException("OPENINFRA_CODE_URL needs OPENINFRA_CODE_TOKEN_FILE, the path of the function's identity token; it is not set");
        ReadToken(tokenFile); // unreadable or empty fails start before any request

        // No proxy (the token goes to the aws-shim and nowhere else) and no redirects (a 3xx fails start).
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromSeconds(30) })
        {
            Timeout = Timeout.InfiniteTimeSpan, // each attempt carries its own deadline
        };
        Directory.CreateDirectory(dest);
        var tmp = Path.Combine(Path.GetTempPath(), $"oi-{Environment.ProcessId}-{Guid.NewGuid():N}.zip");
        try
        {
            long size = 0;
            string got = null;
            for (int attempt = 1; got == null; attempt++)
            {
                try { (size, got) = await GetPackageOnceAsync(client, uri, ReadToken(tokenFile), tmp); }
                catch (RetryableFetchException e)
                {
                    if (attempt >= CodeAttempts)
                        throw new CodeSourceException($"could not fetch the deployment package from {codeUrl} in {CodeAttempts} attempts: {e.Message}");
                    int delay = 1 << (attempt - 1); // 1s, 2s, 4s, 8s
                    Console.Error.WriteLine($"open-infra-runtime: fetching the deployment package: {e.Message}; retrying in {delay}s (attempt {attempt} of {CodeAttempts})");
                    await Task.Delay(TimeSpan.FromSeconds(delay));
                }
            }
            if (got != want)
                throw new CodeSourceException($"the deployment package does not match its recorded SHA-256 (recorded {want[..12]}, fetched {got[..12]})");
            ExtractGuarded(tmp, dest);
            Console.Error.WriteLine($"open-infra-runtime: unpacked the deployment package ({want[..12]}, {size} bytes) into {dest}");
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* never written */ }
        }
    }

    // One GET of the package, streamed into tmp while it is hashed and held to the size cap. Returns
    // (size, sha256 hex); throws RetryableFetchException for a network failure / 5xx / 429, else
    // CodeSourceException.
    static async Task<(long, string)> GetPackageOnceAsync(HttpClient client, Uri uri, string token, string tmp)
    {
        using var cts = new CancellationTokenSource(CodeAttemptTimeout);
        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        HttpResponseMessage resp;
        try { resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token); }
        catch (Exception e) when (e is HttpRequestException || e is IOException || e is OperationCanceledException)
        {
            throw new RetryableFetchException(e is OperationCanceledException
                ? $"no response from {uri.Authority} in {CodeAttemptTimeout.TotalSeconds}s" : e.Message);
        }
        using (resp)
        {
            int status = (int)resp.StatusCode;
            if (status != 200)
            {
                var errBody = await ReadPrefixAsync(resp, cts.Token);
                var msg = $"GET {uri} -> HTTP {status}" + (errBody.Length > 0 ? ": " + errBody : "");
                if (status >= 500 || status == 429) throw new RetryableFetchException(msg);
                throw new CodeSourceException(msg);
            }
            var declared = resp.Content.Headers.ContentLength;
            if (declared > CodeMaxBytes)
                throw new CodeSourceException($"the deployment package is {declared} bytes, over the {CodeMaxBytes} byte (64 MiB) limit");
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long size = 0;
            var buf = new byte[81920];
            using (var outFile = new FileStream(tmp, FileMode.Create, FileAccess.Write))
            {
                Stream body;
                try { body = await resp.Content.ReadAsStreamAsync(cts.Token); }
                catch (Exception e) when (e is HttpRequestException || e is IOException || e is OperationCanceledException)
                {
                    throw new RetryableFetchException($"the download broke off: {e.Message}");
                }
                using (body)
                {
                    while (true)
                    {
                        int n;
                        try { n = await body.ReadAsync(buf.AsMemory(), cts.Token); }
                        catch (Exception e) when (e is HttpRequestException || e is IOException || e is OperationCanceledException)
                        {
                            throw new RetryableFetchException($"the download broke off after {size} bytes: {e.Message}");
                        }
                        if (n == 0) break;
                        size += n;
                        if (size > CodeMaxBytes)
                            throw new CodeSourceException($"the deployment package is over the {CodeMaxBytes} byte (64 MiB) limit");
                        hash.AppendData(buf, 0, n);
                        await outFile.WriteAsync(buf.AsMemory(0, n));
                    }
                }
            }
            if (declared.HasValue && size != declared.Value)
                throw new RetryableFetchException($"the download broke off after {size} of {declared} bytes");
            return (size, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
        }
    }

    // The first 200 characters of an error response's body (reading no more than 4 KiB of it).
    static async Task<string> ReadPrefixAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            using var s = await resp.Content.ReadAsStreamAsync(ct);
            var buf = new byte[4096];
            int total = 0, n;
            while (total < buf.Length && (n = await s.ReadAsync(buf.AsMemory(total), ct)) > 0) total += n;
            var text = Encoding.UTF8.GetString(buf, 0, total);
            return text.Length > 200 ? text[..200] : text;
        }
        catch { return ""; }
    }

    // Unpack the package into dest, refusing the WHOLE package if any entry is absolute or has a ".."
    // segment (ExtractToDirectory would stop only at an entry that escapes, part-way through unpacking).
    static void ExtractGuarded(string zipPath, string dest)
    {
        var root = Path.GetFullPath(dest);
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var entry in zip.Entries)
        {
            var name = entry.FullName;
            var full = Path.GetFullPath(Path.Combine(root, name));
            if (name.StartsWith('/') || name.StartsWith('\\') || name.Split('/', '\\').Contains("..") ||
                (full != root && !full.StartsWith(rootPrefix, StringComparison.Ordinal)))
                throw new CodeSourceException($"the deployment package has an entry that would unpack outside {dest}, refused: '{name}'");
        }
        zip.ExtractToDirectory(dest, overwriteFiles: true);
    }

    // Resolve the handler's dependencies from /var/task and the .NET layer dir (/opt/dotnet) — the
    // published handler carries its deps there.
    static void InstallResolver()
    {
        var dirs = new[] { TaskDir, Path.Combine(OptDir, "dotnet") };
        AssemblyLoadContext.Default.Resolving += (ctx, name) =>
        {
            foreach (var d in dirs)
            {
                var path = Path.Combine(d, name.Name + ".dll");
                if (File.Exists(path)) return ctx.LoadFromAssemblyPath(path);
            }
            return null;
        };
    }

    static void LoadHandler()
    {
        InstallResolver();
        var spec = Environment.GetEnvironmentVariable("OPENINFRA_HANDLER") ?? "";
        var parts = spec.Split("::");
        if (parts.Length != 3)
            throw new Exception($"OPENINFRA_HANDLER must be 'Assembly::Namespace.Type::Method', got '{spec}'");
        var asmPath = Path.Combine(TaskDir, parts[0] + ".dll");
        if (!File.Exists(asmPath)) throw new Exception($"handler assembly not found: {asmPath}");
        var asm = AssemblyLoadContext.Default.LoadFromAssemblyPath(asmPath);
        var type = asm.GetType(parts[1]) ?? throw new Exception($"type '{parts[1]}' not found in {parts[0]}");
        _method = type.GetMethod(parts[2]) ?? throw new Exception($"method '{parts[2]}' not found on {parts[1]}");
        _params = _method.GetParameters();
        _target = _method.IsStatic ? null : Activator.CreateInstance(type);
    }

    static async Task<object> InvokeAsync(string eventJson, System.Collections.Specialized.NameValueCollection headers, string requestId)
    {
        var args = new object[_params.Length];
        // Bind by parameter TYPE, not position: AWS's .NET runtime accepts (), (TIn), (TIn, ctx) and
        // (ctx), so the ILambdaContext can be absent, first or second. Detect it by type (full name, to
        // avoid referencing Amazon.Lambda.Core) -> context proxy; the event deserializes into any
        // non-context parameter. Fixes a context-only handler, which previously had the event JSON
        // deserialized into the ILambdaContext interface (NotSupportedException -> 502).
        for (int i = 0; i < _params.Length; i++)
        {
            var pt = _params[i].ParameterType;
            args[i] = IsLambdaContextType(pt) ? LambdaContextProxy.Create(pt, headers, requestId) : DeserializeEvent(eventJson, pt);
        }
        var result = _method.Invoke(_target, args);
        if (result is Task task)
        {
            await task.ConfigureAwait(false);
            var rt = task.GetType();
            result = rt.IsGenericType ? rt.GetProperty("Result")!.GetValue(task) : null;
        }
        return result;
    }

    // The ILambdaContext parameter, identified by type name so the shim never references
    // Amazon.Lambda.Core (matches any version of the handler's own context type).
    static bool IsLambdaContextType(Type t) => t.IsInterface && t.FullName == "Amazon.Lambda.Core.ILambdaContext";

    static object DeserializeEvent(string json, Type t)
    {
        if (t == typeof(string)) return json;
        if (typeof(Stream).IsAssignableFrom(t)) return new MemoryStream(Encoding.UTF8.GetBytes(json));
        if (t == typeof(JsonElement)) return JsonSerializer.Deserialize<JsonElement>(json);
        return JsonSerializer.Deserialize(string.IsNullOrWhiteSpace(json) ? "{}" : json, t);
    }

    static void Serve()
    {
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://+:{Port}/");
        listener.Start();
        while (true)
        {
            var ctx = listener.GetContext();
            _ = Task.Run(() => Handle(ctx));
        }
    }

    static async Task Handle(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        try
        {
            if (req.HttpMethod == "GET" && req.Url.AbsolutePath == "/_openinfra_health")
            {
                Send(ctx, 200, "{\"ok\":true}"); return;
            }
            string body;
            using (var sr = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8)) body = await sr.ReadToEndAsync();

            // Direct-invoke mode (AWS `Invoke` semantics) when the caller sets X-Openinfra-Invoke: direct —
            // the shim's Invoke, open-appsync, and Step Functions all do. The raw return value is the
            // payload (a {statusCode,...} object is DATA, never an HTTP mapping), a thrown error is
            // signalled by X-Amz-Function-Error with HTTP still 200, and the event is passed verbatim (no
            // _http). Without the header the legacy API-Gateway proxy mapping applies — API GW only.
            bool direct = string.Equals(req.Headers["X-Openinfra-Invoke"], "direct", StringComparison.Ordinal);
            string eventJson = BuildEvent(body, req, direct);
            object result;
            var requestId = LambdaContextProxy.RequestIdFrom(req.Headers);
            var cap = direct && req.Headers["X-Amz-Log-Type"] == "Tail" ? new LogCapture() : null;
            void AttachTail()
            {
                LogCapture.Current.Value = null;
                if (cap != null)
                    ctx.Response.Headers["X-Amz-Log-Result"] = cap.Tail(requestId, LambdaContextProxy.VersionFrom(req.Headers), LambdaContextProxy.MemoryMb());
            }
            LogCapture.Current.Value = cap;
            try { result = await InvokeAsync(eventJson, req.Headers, requestId); }
            catch (Exception e)
            {
                var inner = (e as TargetInvocationException)?.InnerException ?? e;
                Console.Error.WriteLine("open-infra-runtime: handler raised:\n" + inner);
                AttachTail();
                var errJson = JsonSerializer.Serialize(new { errorType = inner.GetType().Name, errorMessage = inner.Message });
                if (direct) Send(ctx, 200, errJson, "application/json", "Unhandled");
                else Send(ctx, 502, errJson);
                return;
            }
            AttachTail();
            WriteResult(ctx, result, direct);
        }
        catch (Exception e)
        {
            try { Send(ctx, 500, JsonSerializer.Serialize(new { errorType = "InternalError", errorMessage = e.Message })); } catch { }
        }
    }

    static string BuildEvent(string body, HttpListenerRequest req, bool direct)
    {
        JsonNode node;
        try { node = string.IsNullOrWhiteSpace(body) ? new System.Text.Json.Nodes.JsonObject() : JsonNode.Parse(body); }
        catch { node = new System.Text.Json.Nodes.JsonObject { ["body"] = body }; }
        // AWS Invoke: any JSON payload is the event as sent — a list (AppSync's BatchInvoke), a string,
        // null — with no _http. Only the proxy mapping needs an object to carry _http.
        if (direct) return node is null ? "null" : node.ToJsonString();
        if (node is not System.Text.Json.Nodes.JsonObject obj)
            obj = new System.Text.Json.Nodes.JsonObject { ["body"] = node };
        var headers = new System.Text.Json.Nodes.JsonObject();
        foreach (string h in req.Headers) headers[h] = req.Headers[h];
        obj["_http"] = new System.Text.Json.Nodes.JsonObject
        {
            ["method"] = req.HttpMethod,
            ["path"] = req.Url.AbsolutePath,
            ["query"] = req.Url.Query.TrimStart('?'),
            ["headers"] = headers,
        };
        return obj.ToJsonString();
    }

    // API-Gateway proxy shape (an object with statusCode) -> used verbatim; anything else -> 200 + JSON.
    // In direct-invoke mode the raw value IS the payload — never an HTTP proxy mapping.
    static void WriteResult(HttpListenerContext ctx, object result, bool direct)
    {
        var json = result is string s ? s : (result == null ? "null" : JsonSerializer.Serialize(result));
        if (direct) { Send(ctx, 200, json); return; }
        try
        {
            var el = JsonSerializer.Deserialize<JsonElement>(json);
            if (el.ValueKind == JsonValueKind.Object && TryGetCI(el, "statusCode", out var sc))
            {
                int status = sc.ValueKind == JsonValueKind.Number ? sc.GetInt32() : 200;
                string respBody = TryGetCI(el, "body", out var b)
                    ? (b.ValueKind == JsonValueKind.String ? b.GetString() : b.GetRawText()) : "";
                string ctype = "application/json";
                if (TryGetCI(el, "headers", out var hs) && hs.ValueKind == JsonValueKind.Object)
                    foreach (var h in hs.EnumerateObject())
                        if (string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)) ctype = h.Value.GetString();
                Send(ctx, status, respBody, ctype);
                return;
            }
        }
        catch { /* not an object / not JSON — fall through to 200 */ }
        Send(ctx, 200, json);
    }

    static bool TryGetCI(JsonElement obj, string name, out JsonElement val)
    {
        foreach (var p in obj.EnumerateObject())
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) { val = p.Value; return true; }
        val = default; return false;
    }

    static void Send(HttpListenerContext ctx, int status, string body, string contentType = "application/json", string functionError = null)
    {
        var bytes = Encoding.UTF8.GetBytes(body ?? "");
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = contentType;
        if (functionError != null) ctx.Response.Headers["X-Amz-Function-Error"] = functionError;
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        ctx.Response.OutputStream.Close();
    }
}
