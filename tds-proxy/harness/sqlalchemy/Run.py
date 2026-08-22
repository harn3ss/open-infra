# Drives the 5 grid shapes through the proxy via SQLAlchemy (an ORM/toolkit) over pyodbc — issue #3 asks
# for "at least one ORM". An ORM sits ON TOP of a driver, so the proxy sees the driver's RPCs shaped by
# the ORM's patterns (autobegin transactions, the Core expression language's parameter binding, etc.).
# Each engine.connect() (with pooling disabled) is a distinct proxy session.
import os
import sys
from sqlalchemy import create_engine, text

host = os.environ["HOST"]
port = os.environ["PORT"]
user = os.environ["USER"]
pw = os.environ["PW"]
enc = os.environ.get("ENCRYPT", "yes")
cert = os.environ.get("CERT")

# mssql+pyodbc with the ODBC Driver 18 params passed through the URL query.
q = f"driver=ODBC+Driver+18+for+SQL+Server&Encrypt={enc}&TrustServerCertificate=yes"
if cert:
    q += f"&ServerCertificate={cert}&HostNameInCertificate=localhost"
url = f"mssql+pyodbc://{user}:{pw}@{host}:{port}/master?{q}"

# NullPool = no SQLAlchemy-side connection pooling, so each connect() opens a fresh proxy session (the
# proxy is the pool under test). pyodbc's own pooling is disabled via the URL below is not enough, so also
# turn it off in the driver.
import pyodbc  # noqa: E402
pyodbc.pooling = False
from sqlalchemy.pool import NullPool  # noqa: E402

engine = create_engine(url, poolclass=NullPool)
print(f"SQLAlchemy(+pyodbc) Encrypt={enc} -> {host}:{port}", flush=True)


def session(label, body):
    try:
        with engine.connect() as cn:
            body(cn)
        print(f"  {label:<22} ok", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  {label:<22} ERR {str(e).splitlines()[0]}", flush=True)


# 1 plain-select — Core expression, no session state → MULTIPLEX.
session("1 plain-select", lambda cn: cn.execute(text("SELECT 1")).fetchall())

# 2 set-nocount — a poolable login prelude → MULTIPLEX.
def _nocount(cn):
    cn.exec_driver_sql("SET NOCOUNT ON")
    cn.execute(text("SELECT 1")).fetchall()
session("2 set-nocount", _nocount)

# 3 temp-table — session-scoped → PIN.
def _temp(cn):
    cn.exec_driver_sql("CREATE TABLE #t(id int)")
    cn.exec_driver_sql("INSERT INTO #t VALUES(1)")
session("3 temp-table", _temp)

# 4 param-prepared — a bound parameter goes through pyodbc → sp_prepexec (prepared handle) → PINS, same
# as raw pyodbc; the ORM does not change the driver's RPC framing.
session("4 param-prepared", lambda cn: cn.execute(text("SELECT :p"), {"p": 42}).fetchall())

# 5 begin-tran — SQLAlchemy's explicit transaction (begin()/commit) → TxMgr request → PINS.
def _txn(cn):
    with cn.begin():
        cn.execute(text("SELECT 1")).fetchall()
session("5 begin-tran", _txn)

sys.exit(0)
