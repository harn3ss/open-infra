# #40 fault-axis harness for pyodbc AND SQLAlchemy (MODE=pyodbc|sqlalchemy), ODBC Driver 18 (Encrypt=yes
# -> proxy terminates TLS). One SCENARIO per invocation; prints FAULT_WINDOW_OPEN at the fault point and a
# single RESULT line. ODBC explicit txn -> TransactionManager (pins); SQLAlchemy 2.0 eng.begin() autobegins
# a real transaction for the unit of work (the ORM worst case #40 calls out).
import os, sys, time
MODE=os.environ.get("MODE","pyodbc")
host=os.environ["HOST"]; port=os.environ["PORT"]; user=os.environ["USER"]; pw=os.environ["PW"]
SC=os.environ["SCENARIO"]; SENT=os.environ.get("SENTINEL","py-x"); SLEEP=int(os.environ.get("FAULT_SLEEP","34"))
def marker(): print("FAULT_WINDOW_OPEN", flush=True)
def trunc(s): return str(s).replace("\n"," ").replace("|","/")[:90]
def RESULT(s): print("RESULT "+s, flush=True)

import pyodbc
pyodbc.pooling=False
CONN=("DRIVER={ODBC Driver 18 for SQL Server};"
      f"SERVER={host},{port};DATABASE=master;UID={user};PWD={pw};Encrypt=yes;TrustServerCertificate=yes")
def pyconn(autocommit=True): return pyodbc.connect(CONN, autocommit=autocommit, timeout=15)
def sa_engine():
    from sqlalchemy import create_engine
    import urllib.parse
    pre_ping = os.environ.get("PRE_PING","0") == "1"  # SA's own pool: pre_ping detects a dead pooled conn
    return create_engine("mssql+pyodbc:///?odbc_connect="+urllib.parse.quote_plus(CONN), pool_pre_ping=pre_ping)
# raw pyodbc cursor for multi-result-set handling, sourced from whichever layer we're testing
def raw_cursor():
    if MODE=="sqlalchemy":
        eng=sa_engine(); rc=eng.raw_connection(); return rc, rc.cursor()
    cn=pyconn(); return cn, cn.cursor()

BATCH="SELECT TOP 1000 a.object_id FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:12'; SELECT TOP 1 object_id FROM sys.all_objects"

try:
  if SC=="failover-idle":
    if MODE=="pyodbc":
      cn=pyconn(); cur=cn.cursor(); cur.execute("SELECT 1").fetchall(); marker(); time.sleep(SLEEP)
      ok=False; detail=""
      try: cur.execute("SELECT 1").fetchall(); ok=True; detail="same-conn"
      except Exception as e: detail="same:"+trunc(e)
      if not ok:
        try: cn2=pyconn(); cn2.cursor().execute("SELECT 1").fetchall(); ok=True; detail="fresh-conn"; cn2.close()
        except Exception as e: detail="fresh:"+trunc(e)
      RESULT(f"failover-idle recovered={ok} detail={detail}")
    else:
      from sqlalchemy import text
      eng=sa_engine()
      with eng.connect() as c: c.execute(text("SELECT 1")).fetchall()
      marker(); time.sleep(SLEEP)
      ok=False; detail=""
      try:
        with eng.connect() as c: c.execute(text("SELECT 1")).fetchall()
        ok=True; detail="engine-reconnect"
      except Exception as e: detail=trunc(e)
      RESULT(f"failover-idle recovered={ok} detail={detail}")
  elif SC=="failover-during-txn":
    cn0=pyconn(); cn0.cursor().execute("IF OBJECT_ID('dbo.grid_sentinel') IS NULL CREATE TABLE dbo.grid_sentinel(v varchar(64))"); cn0.close()
    errRaised=False; detail=""
    if MODE=="pyodbc":
      cn=pyconn(autocommit=False)  # ODBC explicit txn -> TransactionManager (pins)
      cn.cursor().execute(f"INSERT INTO dbo.grid_sentinel VALUES('{SENT}')")
      marker(); time.sleep(SLEEP)
      try: cn.commit(); detail="commit-returned"
      except Exception as e: errRaised=True; detail=trunc(e)
      try: cn.close()
      except Exception: pass
    else:
      from sqlalchemy import text
      eng=sa_engine()
      try:
        with eng.begin() as c:  # SQLAlchemy 2.0 autobegin: a real txn for the unit of work
          c.execute(text(f"INSERT INTO dbo.grid_sentinel VALUES('{SENT}')"))
          marker(); time.sleep(SLEEP)
        detail="commit-returned"  # exiting eng.begin() commits
      except Exception as e: errRaised=True; detail=trunc(e)
    committed=False
    for _ in range(30):
      try:
        cc=pyconn(); n=cc.cursor().execute(f"SELECT COUNT(*) FROM dbo.grid_sentinel WHERE v='{SENT}'").fetchone()[0]; committed=n>0; cc.close(); break
      except Exception: time.sleep(2)
    RESULT(f"failover-during-txn errorRaised={errRaised} committed={committed} detail={detail}")
  elif SC=="midresult-drop":
    rows=0; errRaised=False; detail=""; first=True
    try:
      rc, cur = raw_cursor(); cur.execute(BATCH)
      while True:
        r=cur.fetchone()
        if r is None: break
        rows+=1
        if first: first=False; marker()
      while cur.nextset():          # advance past the WAITFOR -> blocks -> backend killed -> error
        while True:
          r=cur.fetchone()
          if r is None: break
          rows+=1
    except Exception as e: errRaised=True; detail=trunc(e)
    RESULT(f"midresult-drop errorRaised={errRaised} rowsRead={rows} detail={detail}")
  elif SC=="pinned-discard":
    cn=pyconn(); cn.cursor().execute("CREATE TABLE #pinme(x int)")  # session temp -> pins
    RESULT("pinned-discard pinned=true"); marker()
    os._exit(0)  # hard drop while pinned
  elif SC=="pin-hold":
    try:
      cn=pyconn(); cn.cursor().execute("CREATE TABLE #hold(x int)"); RESULT("pin-hold acquired=true"); time.sleep(SLEEP); cn.close()
    except Exception as e: RESULT("pin-hold acquired=false detail="+trunc(e))
  else: RESULT("unknown-scenario "+SC)
except Exception as e:
  RESULT(f"{SC} errorRaised=true detail={trunc(e)}")
sys.exit(0)
