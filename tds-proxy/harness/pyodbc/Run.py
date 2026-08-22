# Drives the 5 grid shapes through the proxy, each on its own pyodbc connection (= one proxy session).
# pyodbc + ODBC Driver 18. ODBC Driver 18 defaults to Encrypt=yes (the mandatory/tunneled encryption),
# so this exercises the proxy's TLS termination (#6). It also frames prepared statements differently
# from go-mssqldb/JDBC (sp_prepare / sp_prepexec vs sp_executesql) — the point of covering it for #3.
import os
import sys
import pyodbc

# pyodbc enables ODBC connection pooling by default, which would collapse the 5 shapes onto ONE underlying
# connection (= one proxy session) and defeat the per-shape test. Disable it so each connect() is a
# distinct proxy session, exactly as the go-mssqldb/JDBC harnesses behave.
pyodbc.pooling = False

host = os.environ["HOST"]
port = os.environ["PORT"]
user = os.environ["USER"]
pw = os.environ["PW"]
enc = os.environ.get("ENCRYPT", "yes")  # yes = mandatory (tunneled); strict = TDS 8.0

conn_str = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    f"SERVER={host},{port};DATABASE=master;UID={user};PWD={pw};"
    f"Encrypt={enc};TrustServerCertificate=yes"
)
# Encrypt=strict (TDS 8.0) validates the server cert and IGNORES TrustServerCertificate; point the driver
# at the proxy's cert via the ServerCertificate keyword (ODBC Driver 18.1+) so strict can trust it.
cert = os.environ.get("CERT")
if cert:
    conn_str += f";ServerCertificate={cert};HostNameInCertificate=localhost"
print(f"pyodbc Encrypt={enc} -> {host}:{port}", flush=True)


def session(label, body):
    try:
        cn = pyodbc.connect(conn_str, autocommit=True, timeout=15)
        try:
            body(cn)
            print(f"  {label:<22} ok", flush=True)
        finally:
            cn.close()
    except Exception as e:  # noqa: BLE001 — harness wants the message, not a traceback
        print(f"  {label:<22} ERR {str(e).splitlines()[0]}", flush=True)


# 1 plain-select — no session state → should MULTIPLEX.
session("1 plain-select", lambda cn: cn.cursor().execute("SELECT 1").fetchall())

# 2 set-nocount — SET NOCOUNT ON is a re-applied login prelude, not leaked state → MULTIPLEX.
def _nocount(cn):
    c = cn.cursor()
    c.execute("SET NOCOUNT ON")
    c.execute("SELECT 1").fetchall()
session("2 set-nocount", _nocount)

# 3 temp-table — #t is session-scoped → must PIN.
def _temp(cn):
    c = cn.cursor()
    c.execute("CREATE TABLE #t(id int)")
    c.execute("INSERT INTO #t VALUES(1)")
session("3 temp-table", _temp)

# 4 param-prepared — a parameterized query; ODBC frames this via sp_prepare/sp_prepexec/sp_executesql.
# Exec-scoped (no leaked prepared handle held open) → should MULTIPLEX; this is the RPC-verdict check.
def _param(cn):
    c = cn.cursor()
    c.execute("SELECT ?", 42).fetchall()
session("4 param-prepared", _param)

# 5 begin-tran — an explicit transaction, committed. autocommit off for the scope, then commit.
def _txn(cn):
    cn.autocommit = False
    c = cn.cursor()
    c.execute("SELECT 1").fetchall()
    cn.commit()
    cn.autocommit = True
session("5 begin-tran", _txn)

sys.exit(0)
