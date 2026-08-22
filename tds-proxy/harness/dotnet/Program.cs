// Drives the 5 grid shapes through the proxy, each on its own SqlConnection (= one proxy session).
// Microsoft.Data.SqlClient speaks TDS directly (not ODBC). It negotiates encryption, so this exercises
// the proxy's TLS termination (#6): Encrypt=Mandatory (tunneled) or Encrypt=Strict (TDS 8.0). Pooling is
// disabled (Pooling=false) so each Open() is a distinct proxy session, matching the other harnesses.
using System;
using System.Threading;
using Microsoft.Data.SqlClient;

class Run
{
    static string connStr;

    static void Session(string label, Action<SqlConnection> body)
    {
        try
        {
            using var cn = new SqlConnection(connStr);
            cn.Open();
            body(cn);
            Console.WriteLine($"  {label,-22} ok");
        }
        catch (Exception e)
        {
            Console.WriteLine($"  {label,-22} ERR {e.Message.Split('\n')[0]}");
        }
    }

    static void Main()
    {
        string host = Environment.GetEnvironmentVariable("HOST");
        string port = Environment.GetEnvironmentVariable("PORT");
        string user = Environment.GetEnvironmentVariable("USER");
        string pw = Environment.GetEnvironmentVariable("PW");
        string enc = Environment.GetEnvironmentVariable("ENCRYPT") ?? "Mandatory"; // Mandatory=tunneled, Strict=TDS 8.0

        var b = new SqlConnectionStringBuilder
        {
            DataSource = $"{host},{port}",
            InitialCatalog = "master",
            UserID = user,
            Password = pw,
            Encrypt = enc.Equals("Strict", StringComparison.OrdinalIgnoreCase)
                ? SqlConnectionEncryptOption.Strict
                : SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = true, // ignored under Strict — see ServerCertificate
            Pooling = false,
            ConnectTimeout = 15,
        };
        string cert = Environment.GetEnvironmentVariable("CERT");
        if (!string.IsNullOrEmpty(cert))
        {
            b.ServerCertificate = cert;      // Strict validates the chain; pin the proxy cert (5.1+)
            b.HostNameInCertificate = "localhost";
        }
        connStr = b.ConnectionString;
        Console.WriteLine($"Microsoft.Data.SqlClient Encrypt={enc} -> {host}:{port}");

        // 1 plain-select — no session state → should MULTIPLEX.
        Session("1 plain-select", cn =>
        {
            using var c = new SqlCommand("SELECT 1", cn);
            c.ExecuteScalar();
        });

        // 2 set-nocount — SET NOCOUNT ON is a re-applied login prelude → MULTIPLEX.
        Session("2 set-nocount", cn =>
        {
            new SqlCommand("SET NOCOUNT ON", cn).ExecuteNonQuery();
            new SqlCommand("SELECT 1", cn).ExecuteScalar();
        });

        // 3 temp-table — #t is session-scoped → must PIN.
        Session("3 temp-table", cn =>
        {
            new SqlCommand("CREATE TABLE #t(id int)", cn).ExecuteNonQuery();
            new SqlCommand("INSERT INTO #t VALUES(1)", cn).ExecuteNonQuery();
        });

        // 4 param-prepared — a parameterized command; SqlClient sends this via sp_executesql (exec-scoped,
        // no leaked handle) → should MULTIPLEX. This is the RPC-verdict check for the .NET framing.
        Session("4 param-prepared", cn =>
        {
            using var c = new SqlCommand("SELECT @p", cn);
            c.Parameters.AddWithValue("@p", 42);
            c.ExecuteScalar();
        });

        // 5 begin-tran — an explicit transaction, committed. SqlClient issues a TM request → should PIN.
        Session("5 begin-tran", cn =>
        {
            using var tx = cn.BeginTransaction();
            using var c = new SqlCommand("SELECT 1", cn, tx);
            c.ExecuteScalar();
            tx.Commit();
        });

        Thread.Sleep(200); // let the proxy log the last session's classification before exit
    }
}
