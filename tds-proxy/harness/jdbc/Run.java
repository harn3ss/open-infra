// Drives the 5 grid shapes through the proxy, each on its own JDBC connection (= one proxy session).
// mssql-jdbc, encrypt=false (the proxy is TDS-no-TLS). JDBC uses server-side prepared statements
// (sp_prepare) by default, so parameterized queries behave differently from go-mssqldb's sp_executesql.
import java.sql.*;
public class Run {
  static String url;
  static void session(String label, java.util.function.Consumer<Connection> body) {
    try (Connection c = DriverManager.getConnection(url)) { body.accept(c); System.out.println(String.format("  %-22s ok", label)); }
    catch (Exception e) { System.out.println(String.format("  %-22s ERR %s", label, e.getMessage())); }
  }
  public static void main(String[] a) throws Exception {
    String enc = System.getenv("ENCRYPT"); if (enc == null || enc.isEmpty()) enc = "true"; // exercise TLS termination (#6) by default
    url = String.format("jdbc:sqlserver://%s:%s;databaseName=master;user=%s;password=%s;encrypt=%s;trustServerCertificate=true",
      System.getenv("HOST"), System.getenv("PORT"), System.getenv("USER"), System.getenv("PW"), enc);
    String ts = System.getenv("TRUSTSTORE"); // strict (TDS 8.0) validates the chain; trust the proxy cert explicitly
    if (ts != null && !ts.isEmpty())
      url += ";trustStore=" + ts + ";trustStorePassword=" + System.getenv("TRUSTSTORE_PW") + ";hostNameInCertificate=localhost";
    System.out.println("mssql-jdbc encrypt=" + enc + " → " + System.getenv("HOST") + ":" + System.getenv("PORT"));
    session("1 plain-select", c -> { try (Statement s=c.createStatement()) { s.executeQuery("SELECT 1").close(); } catch(Exception e){throw new RuntimeException(e);} });
    session("2 set-nocount", c -> { try (Statement s=c.createStatement()) { s.execute("SET NOCOUNT ON"); s.executeQuery("SELECT 1").close(); } catch(Exception e){throw new RuntimeException(e);} });
    session("3 temp-table", c -> { try (Statement s=c.createStatement()) { s.execute("CREATE TABLE #t(id int)"); s.execute("INSERT INTO #t VALUES(1)"); } catch(Exception e){throw new RuntimeException(e);} });
    session("4 param-prepared", c -> { try (PreparedStatement p=c.prepareStatement("SELECT ?")) { p.setInt(1,42); p.executeQuery().close(); } catch(Exception e){throw new RuntimeException(e);} });
    session("5 begin-tran", c -> { try { c.setAutoCommit(false); try(Statement s=c.createStatement()){ s.executeQuery("SELECT 1").close(); } c.commit(); } catch(Exception e){throw new RuntimeException(e);} });
  }
}
