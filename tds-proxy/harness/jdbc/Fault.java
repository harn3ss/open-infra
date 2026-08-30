// #40 fault-axis harness for mssql-jdbc. One SCENARIO per invocation; drives the workload through the
// proxy while the orchestrator (harness/fault-matrix.sh) injects the backend fault, and prints a single
// RESULT line the orchestrator parses. encrypt=false (proxy is TDS-no-TLS on this port).
// JDBC txn semantics: setAutoCommit(false) -> SET IMPLICIT_TRANSACTIONS ON (poolable prelude), the
// per-driver divergence #40 is about.
import java.sql.*;
public class Fault {
  static String url;
  static Connection conn() throws Exception { return DriverManager.getConnection(url); }
  static String trunc(String s){ if(s==null) return ""; s=s.replace("\n"," ").replace("|","/"); return s.length()>90? s.substring(0,90): s; }
  static void marker(){ System.out.println("FAULT_WINDOW_OPEN"); System.out.flush(); }

  public static void main(String[] a) throws Exception {
    String enc = System.getenv().getOrDefault("ENCRYPT","false");
    url = String.format("jdbc:sqlserver://%s:%s;databaseName=master;user=%s;password=%s;encrypt=%s;trustServerCertificate=true;loginTimeout=6",
      System.getenv("HOST"), System.getenv("PORT"), System.getenv("USER"), System.getenv("PW"), enc);
    String sc = System.getenv("SCENARIO");
    String sentinel = System.getenv().getOrDefault("SENTINEL","jdbc-x");
    int sleep = Integer.parseInt(System.getenv().getOrDefault("FAULT_SLEEP","30"));

    if (sc.equals("failover-idle")) {
      try (Connection c=conn(); Statement s=c.createStatement()) {
        s.executeQuery("SELECT 1").close();
        marker(); Thread.sleep(sleep*1000L);
        boolean ok=false; String detail="";
        try { s.executeQuery("SELECT 1").close(); ok=true; detail="same-conn"; }
        catch(Exception e){ detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); }
        if(!ok){ try(Connection c2=conn(); Statement s2=c2.createStatement()){ s2.executeQuery("SELECT 1").close(); ok=true; detail="fresh-conn"; } catch(Exception e){ detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); } }
        System.out.println("RESULT failover-idle recovered="+ok+" detail="+detail);
      }
    } else if (sc.equals("failover-during-txn")) {
      try(Connection c0=conn(); Statement s0=c0.createStatement()){ s0.execute("IF OBJECT_ID('dbo.grid_sentinel') IS NULL CREATE TABLE dbo.grid_sentinel(v varchar(64))"); }
      boolean errRaised=false; String detail="";
      try (Connection c=conn()) {
        c.setAutoCommit(false);
        try(Statement s=c.createStatement()){ s.executeUpdate("INSERT INTO dbo.grid_sentinel VALUES('"+sentinel+"')"); }
        marker(); Thread.sleep(sleep*1000L);
        try { c.commit(); detail="commit-returned"; } catch(Exception e){ errRaised=true; detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); }
      } catch(Exception e){ errRaised=true; detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); }
      boolean committed=false;
      for(int i=0;i<30 && !committed;i++){ try(Connection c=conn(); Statement s=c.createStatement()){ ResultSet rs=s.executeQuery("SELECT COUNT(*) FROM dbo.grid_sentinel WHERE v='"+sentinel+"'"); rs.next(); committed=rs.getInt(1)>0; break; } catch(Exception e){ Thread.sleep(2000); } }
      System.out.println("RESULT failover-during-txn errorRaised="+errRaised+" committed="+committed+" detail="+detail);
    } else if (sc.equals("midresult-drop")) {
      // Force SERVER-CURSOR streaming (selectMethod=cursor + fetchSize) so rows arrive incrementally as
      // we iterate; pace the read so the backend kill lands WHILE fetching. A clean client sees an error,
      // never a truncated set that looks complete.
      int rows=0; boolean errRaised=false; String detail="";
      try (Connection c=DriverManager.getConnection(url+";selectMethod=cursor"); Statement s=c.createStatement()) {
        s.setFetchSize(100);
        ResultSet rs=s.executeQuery("SELECT TOP 100000 a.object_id FROM sys.all_objects a CROSS JOIN sys.all_objects b");
        if(rs.next()) rows++;
        marker();
        try { while(rs.next()){ rows++; if(rows%100==0) Thread.sleep(15); } } catch(Exception e){ errRaised=true; detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); }
      } catch(Exception e){ errRaised=true; detail=e.getClass().getSimpleName()+":"+trunc(e.getMessage()); }
      System.out.println("RESULT midresult-drop errorRaised="+errRaised+" rowsRead="+rows+" detail="+detail);
    } else if (sc.equals("pinned-discard")) {
      Connection c=conn(); Statement s=c.createStatement();
      s.execute("CREATE TABLE #pinme(x int)"); // real server-side temp -> pins the backend
      System.out.println("RESULT pinned-discard pinned=true"); System.out.flush();
      marker();
      Runtime.getRuntime().halt(0); // hard-exit -> OS drops the socket while pinned (no graceful drain)
    } else if (sc.equals("pin-hold")) {
      try(Connection c=conn(); Statement s=c.createStatement()){
        s.execute("CREATE TABLE #hold(x int)");
        System.out.println("RESULT pin-hold acquired=true"); System.out.flush();
        Thread.sleep(sleep*1000L);
      } catch(Exception e){ System.out.println("RESULT pin-hold acquired=false detail="+e.getClass().getSimpleName()+":"+trunc(e.getMessage())); }
    } else {
      System.out.println("RESULT unknown-scenario "+sc);
    }
  }
}
