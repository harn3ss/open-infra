// open-infra Lambda runtime shim (.NET 8) — the "runtime interface" half of the runtime-base-image +
// handler-shim ingestion model (kind: Function spec.code). The .NET sibling of bootstrap.py /
// bootstrap.js, speaking the EXACT same env contract so the composition wires all three identically.
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
using System.IO.Compression;
using System.Net;
using System.Reflection;
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
        var endpoint = Environment.GetEnvironmentVariable("AWS_ENDPOINT_URL");
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
        Directory.CreateDirectory(dest);
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Read))
            zip.ExtractToDirectory(dest, overwriteFiles: true);
        Console.Error.WriteLine($"open-infra-runtime: unpacked s3://{bucket}/{key} ({ms.Length} bytes) into {dest}");
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
        if (_params.Length >= 1) args[0] = DeserializeEvent(eventJson, _params[0].ParameterType);
        if (_params.Length >= 2) args[1] = LambdaContextProxy.Create(_params[1].ParameterType);
        var result = _method.Invoke(_target, args);
        if (result is Task task)
        {
            await task.ConfigureAwait(false);
            var rt = task.GetType();
            result = rt.IsGenericType ? rt.GetProperty("Result")!.GetValue(task) : null;
        }
        return result;
    }

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

            // The event is the JSON body; attach HTTP facts under _http for HTTP-triggered handlers.
            string eventJson = BuildEvent(body, req);
            object result;
            try { result = await InvokeAsync(eventJson); }
            catch (Exception e)
            {
                var inner = (e as TargetInvocationException)?.InnerException ?? e;
                Console.Error.WriteLine("open-infra-runtime: handler raised:\n" + inner);
                Send(ctx, 502, JsonSerializer.Serialize(new { errorType = inner.GetType().Name, errorMessage = inner.Message }));
                return;
            }
            WriteResult(ctx, result);
        }
        catch (Exception e)
        {
            try { Send(ctx, 500, JsonSerializer.Serialize(new { errorType = "InternalError", errorMessage = e.Message })); } catch { }
        }
    }

    static string BuildEvent(string body, HttpListenerRequest req)
    {
        JsonNode node;
        try { node = string.IsNullOrWhiteSpace(body) ? new System.Text.Json.Nodes.JsonObject() : JsonNode.Parse(body); }
        catch { node = new System.Text.Json.Nodes.JsonObject { ["body"] = body }; }
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
    static void WriteResult(HttpListenerContext ctx, object result)
    {
        var json = result is string s ? s : (result == null ? "null" : JsonSerializer.Serialize(result));
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

    static void Send(HttpListenerContext ctx, int status, string body, string contentType = "application/json")
    {
        var bytes = Encoding.UTF8.GetBytes(body ?? "");
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = contentType;
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        ctx.Response.OutputStream.Close();
    }
}
