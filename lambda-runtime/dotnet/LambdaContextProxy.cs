// Supplies an ILambdaContext (and its Logger) of the HANDLER'S OWN types via DispatchProxy, so any
// Amazon.Lambda.Core version is satisfied without this shim referencing the package (no assembly-
// identity / version-binding hazard). Members are answered by name; anything unhandled returns the
// member's default.
using System.Reflection;

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
    string _reqId;
    DateTime _deadline;
    object _logger; // a DispatchProxy of the handler's ILambdaLogger type (or null)

    public static object Create(Type ifaceType)
    {
        var proxy = (LambdaContextProxy)ProxyFactory.Make(ifaceType, typeof(LambdaContextProxy));
        proxy._reqId = Guid.NewGuid().ToString();
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
            case "get_FunctionName": return Environment.GetEnvironmentVariable("OPENINFRA_FUNCTION_NAME") ?? "function";
            case "get_FunctionVersion": return "$LATEST";
            case "get_InvokedFunctionArn": return "";
            case "get_LogGroupName": return "";
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
