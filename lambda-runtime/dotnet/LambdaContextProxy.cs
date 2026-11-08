// Supplies an ILambdaContext (and its Logger) of the HANDLER'S OWN types via DispatchProxy, so any
// Amazon.Lambda.Core version is satisfied without this shim referencing the package (no assembly-
// identity / version-binding hazard). Members are answered by name; anything unhandled returns the
// member's default.
using System.Collections.Specialized;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

// DispatchProxy exposes more than one static `Create` in .NET 8, so GetMethod("Create") is ambiguous;
// select the generic `Create<T,TProxy>()` (2 type params, 0 value params) explicitly.
static class ProxyFactory
{
    static readonly MethodInfo Create = typeof(DispatchProxy)
        .GetMethods(BindingFlags.Public | BindingFlags.Static)
        .First(m => m.Name == "Create" && m.IsGenericMethodDefinition
                 && m.GetGenericArguments().Length == 2 && m.GetParameters().Length == 0);

    public static object Make(Type ifaceType, Type proxyType) =>
        Create.MakeGenericMethod(ifaceType, proxyType).Invoke(null, null);
}

public class LambdaContextProxy : DispatchProxy
{
    static readonly string FunctionName = Environment.GetEnvironmentVariable("OPENINFRA_FUNCTION_NAME") ?? "function";
    static readonly Regex VersionRe = new Regex(@"^(\$LATEST|[1-9][0-9]{0,8})$");
    static readonly Regex RoleAccountRe = new Regex(@"^arn:aws[a-z-]*:iam::(\d{12}):role/");
    static readonly Regex OwnArnRe = new Regex(@"^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:" + Regex.Escape(FunctionName) + @"(:[A-Za-z0-9$_-]{1,128})?$");

    string _reqId;
    DateTime _deadline;
    object _logger; // a DispatchProxy of the handler's ILambdaLogger type (or null)
    string _invokedArn, _version;
    JsonElement? _clientContext;

    public static object Create(Type ifaceType, NameValueCollection headers = null)
    {
        var proxy = (LambdaContextProxy)ProxyFactory.Make(ifaceType, typeof(LambdaContextProxy));
        proxy._reqId = Guid.NewGuid().ToString();
        // The ARN the function was invoked by: the one its caller passes, taken only when it names this
        // function; else the function's own ARN, from its region and its role's account; "" when unknown.
        var given = headers?["X-Openinfra-Invoked-Function-Arn"] ?? "";
        var acct = RoleAccountRe.Match(Environment.GetEnvironmentVariable("AWS_ROLE_ARN") ?? "");
        var region = Environment.GetEnvironmentVariable("AWS_REGION") ?? "";
        proxy._invokedArn = OwnArnRe.IsMatch(given) ? given
            : acct.Success && region != "" ? $"arn:aws:lambda:{region}:{acct.Groups[1].Value}:function:{FunctionName}" : "";
        var version = headers?["X-Openinfra-Function-Version"] ?? "";
        proxy._version = VersionRe.IsMatch(version) ? version : "$LATEST";
        var cc = headers?["X-Amz-Client-Context"];
        if (!string.IsNullOrEmpty(cc))
        {
            try
            {
                var doc = JsonDocument.Parse(Convert.FromBase64String(cc));
                if (doc.RootElement.ValueKind == JsonValueKind.Object) proxy._clientContext = doc.RootElement;
            }
            catch (Exception) { /* not base64 JSON: no client context, as when none is passed */ }
        }
        var secs = int.TryParse(Environment.GetEnvironmentVariable("OPENINFRA_TIMEOUT_S"), out var s) ? s : 300;
        proxy._deadline = DateTime.UtcNow.AddSeconds(secs);
        var loggerProp = ifaceType.GetProperty("Logger");
        if (loggerProp != null && loggerProp.PropertyType.IsInterface)
            proxy._logger = LambdaLoggerProxy.Create(loggerProp.PropertyType);
        return proxy;
    }

    protected override object Invoke(MethodInfo targetMethod, object[] args)
    {
        switch (targetMethod.Name)
        {
            case "get_AwsRequestId": return _reqId;
            case "get_FunctionName": return FunctionName;
            case "get_FunctionVersion": return _version ?? "$LATEST";
            case "get_InvokedFunctionArn": return _invokedArn ?? "";
            case "get_LogGroupName": return "/aws/lambda/" + FunctionName;
            case "get_ClientContext":
                return _clientContext.HasValue && targetMethod.ReturnType.IsInterface
                    ? ClientContextProxy.Create(targetMethod.ReturnType, _clientContext.Value) : null;
            case "get_LogStreamName": return "";
            case "get_MemoryLimitInMB":
                return int.TryParse(Environment.GetEnvironmentVariable("OPENINFRA_MEMORY_MB"), out var m) && m > 0 ? m : 128;
            case "get_RemainingTime":
                var rem = _deadline - DateTime.UtcNow; return rem > TimeSpan.Zero ? rem : TimeSpan.Zero;
            case "get_Logger": return _logger;
            default: return Default(targetMethod.ReturnType);
        }
    }

    internal static object Default(Type t) =>
        t == typeof(void) || !t.IsValueType ? null : Activator.CreateInstance(t);
}

// The ClientContext a caller passed to Invoke (IClientContext of the handler's own types): its Environment,
// Custom and Client, as Lambda's .NET runtime gives them.
public class ClientContextProxy : DispatchProxy
{
    JsonElement _doc;

    public static object Create(Type ifaceType, JsonElement doc)
    {
        var proxy = (ClientContextProxy)ProxyFactory.Make(ifaceType, typeof(ClientContextProxy));
        proxy._doc = doc;
        return proxy;
    }

    internal static Dictionary<string, string> Strings(JsonElement doc, string name)
    {
        if (!doc.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.Object) return null;
        var d = new Dictionary<string, string>();
        foreach (var p in e.EnumerateObject())
            d[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText();
        return d;
    }

    protected override object Invoke(MethodInfo targetMethod, object[] args)
    {
        switch (targetMethod.Name)
        {
            case "get_Environment": return Strings(_doc, "env");
            case "get_Custom": return Strings(_doc, "custom");
            case "get_Client":
                return _doc.TryGetProperty("client", out var c) && c.ValueKind == JsonValueKind.Object && targetMethod.ReturnType.IsInterface
                    ? ClientApplicationProxy.Create(targetMethod.ReturnType, c) : null;
            default: return LambdaContextProxy.Default(targetMethod.ReturnType);
        }
    }
}

// The mobile client in a ClientContext (IClientApplication of the handler's own types).
public class ClientApplicationProxy : DispatchProxy
{
    Dictionary<string, string> _fields;

    public static object Create(Type ifaceType, JsonElement client)
    {
        var proxy = (ClientApplicationProxy)ProxyFactory.Make(ifaceType, typeof(ClientApplicationProxy));
        var holder = JsonDocument.Parse("{\"c\":" + client.GetRawText() + "}").RootElement;
        proxy._fields = ClientContextProxy.Strings(holder, "c") ?? new Dictionary<string, string>();
        return proxy;
    }

    protected override object Invoke(MethodInfo targetMethod, object[] args)
    {
        string key = targetMethod.Name switch
        {
            "get_AppPackageName" => "app_package_name",
            "get_AppTitle" => "app_title",
            "get_AppVersionCode" => "app_version_code",
            "get_AppVersionName" => "app_version_name",
            "get_InstallationId" => "installation_id",
            _ => null,
        };
        if (key != null) return _fields.TryGetValue(key, out var v) ? v : null;
        return LambdaContextProxy.Default(targetMethod.ReturnType);
    }
}

// Routes every ILambdaLogger member (Log / LogLine / LogInformation / LogError / …, any version) to
// stderr, so a handler's logging surfaces in the pod logs. Returns the member's default.
public class LambdaLoggerProxy : DispatchProxy
{
    public static object Create(Type ifaceType) => ProxyFactory.Make(ifaceType, typeof(LambdaLoggerProxy));

    protected override object Invoke(MethodInfo targetMethod, object[] args)
    {
        if (targetMethod.Name.StartsWith("Log"))
        {
            var msg = args != null && args.Length > 0
                ? string.Join(" ", System.Linq.Enumerable.Select(args, a => a?.ToString() ?? "")) : "";
            Console.Error.WriteLine("open-infra-runtime[handler]: " + msg);
        }
        return LambdaContextProxy.Default(targetMethod.ReturnType);
    }
}
