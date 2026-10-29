// open-infra Lambda runtime shim (.NET Core 3.1) — the EOL sibling of lambda-runtime/dotnet (net8).
// Same runtime-interface contract as bootstrap.py / bootstrap.js, so the composition wires it identically.
//
// A user ships a PUBLISHED .NET handler (a Zip of the build output: the handler assembly + its deps),
// not a container. open-infra runs it on THIS prebuilt base image: the zip is unpacked into /var/task
// (a ConfigMap mount, or this shim fetches+unzips the code bucket object at cold start), and the shim
// loads the handler assembly, invokes the declared method by reflection, and serves it over HTTP.
//
// Handler format (AWS .NET convention): OPENINFRA_HANDLER = "Assembly::Namespace.Type::Method".
// Supported signatures: Method(TIn) and Method(TIn, ILambdaContext), sync or Task/Task<T>. TIn is the
// event: a string (raw JSON), a Stream, or any type deserialized from the JSON. An ILambdaContext
// parameter is supplied via a DispatchProxy of the HANDLER'S OWN ILambdaContext type, so any
// Amazon.Lambda.Core version works without the shim referencing it. A thrown/faulted handler -> 502
// {errorType,errorMessage}, never a silent 200. GET /_openinfra_health -> 200.
//
// PORT NOTES vs the net8 shim (identical logic otherwise): explicit usings (no ImplicitUsings on the
// 3.1 SDK); BuildEvent is rewritten off System.Text.Json.Nodes (JsonNode/JsonObject — a .NET 6+ API
// absent in 3.1) onto Utf8JsonWriter + JsonDocument, which exist in .NET Core 3.1; no C# 9 `is not`.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
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
        try
        {
            await FetchCodeAsync();
            LoadHandler();
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

    // Fetch+unzip the handler .zip into /var/task and any layers into /opt at cold start. .NET has a
    // stdlib zip reader (System.IO.Compression), so no external unzip is needed. No-op when the handler
    // is ConfigMap-mounted and no layers are declared.
    static async Task FetchCodeAsync()
    {
        var bucket = Environment.GetEnvironmentVariable("OPENINFRA_CODE_BUCKET");
        var layersRaw = Environment.GetEnvironmentVariable("OPENINFRA_LAYERS") ?? "";
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
        // (ZipArchive defaults to leaveOpen:false), so reading ms.Length after it throws.
        long size = ms.Length;
        Directory.CreateDirectory(dest);
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
            zip.ExtractToDirectory(dest, overwriteFiles: true);
        Console.Error.WriteLine($"open-infra-runtime: unpacked s3://{bucket}/{key} ({size} bytes) into {dest}");
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

    static async Task<object> InvokeAsync(string eventJson)
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
            args[i] = IsLambdaContextType(pt) ? LambdaContextProxy.Create(pt) : DeserializeEvent(eventJson, pt);
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
            try { result = await InvokeAsync(eventJson); }
            catch (Exception e)
            {
                var inner = (e as TargetInvocationException)?.InnerException ?? e;
                Console.Error.WriteLine("open-infra-runtime: handler raised:\n" + inner);
                var errJson = JsonSerializer.Serialize(new { errorType = inner.GetType().Name, errorMessage = inner.Message });
                if (direct) Send(ctx, 200, errJson, "application/json", "Unhandled");
                else Send(ctx, 502, errJson);
                return;
            }
            WriteResult(ctx, result, direct);
        }
        catch (Exception e)
        {
            try { Send(ctx, 500, JsonSerializer.Serialize(new { errorType = "InternalError", errorMessage = e.Message })); } catch { }
        }
    }

    // Build the event JSON. net8's shim uses the mutable System.Text.Json.Nodes DOM (JsonObject), which
    // is a .NET 6+ API absent in 3.1 — so here we stream it with Utf8JsonWriter over a parsed JsonDocument
    // (both present in 3.1): copy the body's object properties through verbatim (or wrap a non-object as
    // {"body": ...}), then attach {"_http": {...}}. Semantics match net8 (our _http wins over any in the
    // body).
    static string BuildEvent(string body, HttpListenerRequest req, bool direct)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            if (!string.IsNullOrWhiteSpace(body))
            {
                JsonDocument doc = null;
                try { doc = JsonDocument.Parse(body); } catch { doc = null; }
                if (doc != null && doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        if (!direct && prop.Name == "_http") continue; // proxy mode: our _http (below) wins; direct: pass verbatim
                        w.WritePropertyName(prop.Name);
                        prop.Value.WriteTo(w);
                    }
                }
                else if (doc != null)
                {
                    w.WritePropertyName("body");
                    doc.RootElement.WriteTo(w);
                }
                else
                {
                    w.WriteString("body", body);
                }
                doc?.Dispose();
            }
            if (!direct) // AWS Invoke passes the event verbatim; only API-Gateway mode attaches _http
            {
                w.WritePropertyName("_http");
                w.WriteStartObject();
                w.WriteString("method", req.HttpMethod);
                w.WriteString("path", req.Url.AbsolutePath);
                w.WriteString("query", req.Url.Query.TrimStart('?'));
                w.WritePropertyName("headers");
                w.WriteStartObject();
                foreach (string h in req.Headers) w.WriteString(h, req.Headers[h]);
                w.WriteEndObject(); // headers
                w.WriteEndObject(); // _http
            }
            w.WriteEndObject(); // root
        }
        return Encoding.UTF8.GetString(ms.ToArray());
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
        foreach (var prop in obj.EnumerateObject())
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase)) { val = prop.Value; return true; }
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
