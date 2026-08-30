// #40 fault-axis harness for Microsoft.Data.SqlClient (.NET 8). One SCENARIO per invocation; prints
// FAULT_WINDOW_OPEN at the fault point and a single RESULT line. Encrypt=Mandatory -> proxy terminates
// TLS. Pooling=false (no client-side pool). SqlTransaction -> TransactionManager request (pins).
using System;
using System.Threading;
using Microsoft.Data.SqlClient;

class Fault
{
    static string cs;
    static SqlConnection Open() { var c = new SqlConnection(cs); c.Open(); return c; }
    static void Marker() { Console.WriteLine("FAULT_WINDOW_OPEN"); Console.Out.Flush(); }
    static string Trunc(string s) { s = (s ?? "").Replace("\n", " ").Replace("|", "/"); return s.Length > 90 ? s.Substring(0, 90) : s; }

    static void Main()
    {
        string host = Environment.GetEnvironmentVariable("HOST"), port = Environment.GetEnvironmentVariable("PORT"),
               user = Environment.GetEnvironmentVariable("USER"), pw = Environment.GetEnvironmentVariable("PW");
        string sc = Environment.GetEnvironmentVariable("SCENARIO"), sent = Environment.GetEnvironmentVariable("SENTINEL") ?? "net-x";
        int sleep = int.Parse(Environment.GetEnvironmentVariable("FAULT_SLEEP") ?? "34");
        var b = new SqlConnectionStringBuilder {
            DataSource = $"{host},{port}", InitialCatalog = "master", UserID = user, Password = pw,
            Encrypt = SqlConnectionEncryptOption.Mandatory, TrustServerCertificate = true, Pooling = false, ConnectTimeout = 15,
        };
        cs = b.ConnectionString;
        try
        {
            if (sc == "failover-idle")
            {
                var cn = Open(); new SqlCommand("SELECT 1", cn).ExecuteScalar(); Marker(); Thread.Sleep(sleep * 1000);
                bool ok = false; string detail = "";
                try { new SqlCommand("SELECT 1", cn).ExecuteScalar(); ok = true; detail = "same-conn"; } catch (Exception e) { detail = "same:" + Trunc(e.Message); }
                if (!ok) { try { using var cn2 = Open(); new SqlCommand("SELECT 1", cn2).ExecuteScalar(); ok = true; detail = "fresh-conn"; } catch (Exception e) { detail = "fresh:" + Trunc(e.Message); } }
                Console.WriteLine($"RESULT failover-idle recovered={ok} detail={detail}");
            }
            else if (sc == "failover-during-txn")
            {
                using (var c0 = Open()) new SqlCommand("IF OBJECT_ID('dbo.grid_sentinel') IS NULL CREATE TABLE dbo.grid_sentinel(v varchar(64))", c0).ExecuteNonQuery();
                bool errRaised = false; string detail = "";
                try
                {
                    var cn = Open(); var tx = cn.BeginTransaction(); // TransactionManager -> pins the backend
                    new SqlCommand($"INSERT INTO dbo.grid_sentinel VALUES('{sent}')", cn, tx).ExecuteNonQuery();
                    Marker(); Thread.Sleep(sleep * 1000);
                    try { tx.Commit(); detail = "commit-returned"; } catch (Exception e) { errRaised = true; detail = Trunc(e.Message); }
                    cn.Dispose();
                }
                catch (Exception e) { errRaised = true; detail = Trunc(e.Message); }
                bool committed = false;
                for (int i = 0; i < 30 && !committed; i++) { try { using var cc = Open(); committed = ((int)new SqlCommand($"SELECT COUNT(*) FROM dbo.grid_sentinel WHERE v='{sent}'", cc).ExecuteScalar()) > 0; break; } catch { Thread.Sleep(2000); } }
                Console.WriteLine($"RESULT failover-during-txn errorRaised={errRaised} committed={committed} detail={detail}");
            }
            else if (sc == "midresult-drop")
            {
                int rows = 0; bool errRaised = false; string detail = "";
                try
                {
                    using var cn = Open();
                    using var cmd = new SqlCommand("SELECT TOP 1000 a.object_id FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:12'; SELECT TOP 1 object_id FROM sys.all_objects", cn);
                    cmd.CommandTimeout = 60;
                    using var rd = cmd.ExecuteReader();
                    bool first = true;
                    do { while (rd.Read()) { rows++; if (first) { first = false; Marker(); } } } while (rd.NextResult());
                }
                catch (Exception e) { errRaised = true; detail = Trunc(e.Message); }
                Console.WriteLine($"RESULT midresult-drop errorRaised={errRaised} rowsRead={rows} detail={detail}");
            }
            else if (sc == "pinned-discard")
            {
                var cn = Open(); new SqlCommand("CREATE TABLE #pinme(x int)", cn).ExecuteNonQuery(); // session temp -> pins
                Console.WriteLine("RESULT pinned-discard pinned=true"); Console.Out.Flush(); Marker();
                Environment.Exit(0); // hard drop while pinned
            }
            else if (sc == "pin-hold")
            {
                try { using var cn = Open(); new SqlCommand("CREATE TABLE #hold(x int)", cn).ExecuteNonQuery(); Console.WriteLine("RESULT pin-hold acquired=true"); Console.Out.Flush(); Thread.Sleep(sleep * 1000); }
                catch (Exception e) { Console.WriteLine("RESULT pin-hold acquired=false detail=" + Trunc(e.Message)); }
            }
            else Console.WriteLine("RESULT unknown-scenario " + sc);
        }
        catch (Exception e) { Console.WriteLine($"RESULT {sc} errorRaised=true detail={Trunc(e.Message)}"); }
    }
}
