// #40 fault-axis harness for tedious (Node). One SCENARIO per invocation; prints FAULT_WINDOW_OPEN at
// the fault point and a single RESULT line the orchestrator parses. encrypt=true (proxy terminates TLS).
// tedious beginTransaction() sends a real TM_BEGIN_XACT (pins); execSqlBatch() sends a raw SQLBatch so a
// #temp is session-scoped (pins), while execSql() wraps in sp_executesql (exec-scoped).
const { Connection, Request } = require('tedious');
const H=process.env.HOST||'127.0.0.1', P=+(process.env.PORT||23433), U=process.env.USER||'sa', PW=process.env.PW;
const SC=process.env.SCENARIO, SENT=process.env.SENTINEL||'ted-x', SLEEP=+(process.env.FAULT_SLEEP||34);
const cfg=()=>({server:H, options:{port:P, encrypt:true, trustServerCertificate:true, database:'master', rowCollectionOnRequestCompletion:false, connectTimeout:8000}, authentication:{type:'default',options:{userName:U,password:PW}}});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const trunc=s=>(''+s).replace(/\n/g,' ').replace(/\|/g,'/').slice(0,90);
const marker=()=>{ console.log('FAULT_WINDOW_OPEN'); };
function connect(){ return new Promise((res,rej)=>{ const c=new Connection(cfg()); c.on('connect',e=>e?rej(e):res(c)); c.on('error',()=>{}); c.connect(); }); }
function exec(c,sql,batch=false){ return new Promise((res,rej)=>{ const req=new Request(sql,e=>e?rej(e):res()); if(batch)c.execSqlBatch(req); else c.execSql(req); }); }
function scalar(c,sql){ return new Promise((res,rej)=>{ let v=null; const req=new Request(sql,e=>e?rej(e):res(v)); req.on('row',cols=>{v=cols[0].value;}); c.execSql(req); }); }
function tx(c,fn){ return new Promise((res,rej)=>c[fn](e=>e?rej(e):res())); }

(async()=>{
 try {
  if(SC==='failover-idle'){
    const c=await connect(); await exec(c,'SELECT 1'); marker(); await sleep(SLEEP*1000);
    let ok=false, detail='';
    try{ await exec(c,'SELECT 1'); ok=true; detail='same-conn'; }catch(e){ detail='same:'+trunc(e.message); }
    if(!ok){ try{ const c2=await connect(); await exec(c2,'SELECT 1'); ok=true; detail='fresh-conn'; c2.close(); }catch(e){ detail='fresh:'+trunc(e.message);} }
    console.log(`RESULT failover-idle recovered=${ok} detail=${detail}`); try{c.close();}catch(e){}
  } else if(SC==='failover-during-txn'){
    const c0=await connect(); await exec(c0,"IF OBJECT_ID('dbo.grid_sentinel') IS NULL CREATE TABLE dbo.grid_sentinel(v varchar(64))"); c0.close();
    const c=await connect(); let errRaised=false, detail='';
    await tx(c,'beginTransaction'); // TM_BEGIN_XACT -> pins the backend
    await exec(c,`INSERT INTO dbo.grid_sentinel VALUES('${SENT}')`);
    marker(); await sleep(SLEEP*1000);
    try{ await tx(c,'commitTransaction'); detail='commit-returned'; }catch(e){ errRaised=true; detail=trunc(e.message); }
    try{c.close();}catch(e){}
    let committed=false;
    for(let i=0;i<30&&!committed;i++){ try{ const cc=await connect(); const n=await scalar(cc,`SELECT COUNT(*) FROM dbo.grid_sentinel WHERE v='${SENT}'`); committed=n>0; cc.close(); break; }catch(e){ await sleep(2000);} }
    console.log(`RESULT failover-during-txn errorRaised=${errRaised} committed=${committed} detail=${detail}`);
  } else if(SC==='midresult-drop'){
    const c=await connect(); let rows=0, errRaised=false, detail='', mk=false;
    // tedious buffers the TCP socket internally, so client-side pacing can't hold a single result set
    // open on localhost. Use a DETERMINISTIC window instead: a multi-statement batch that returns partial
    // rows, then WAITFORs; the backend is killed during the WAITFOR while the client awaits the rest.
    // A clean client errors on the aborted batch; a broken one would return the partial rows as complete.
    await new Promise((res)=>{ const req=new Request("SELECT TOP 1000 a.object_id FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:12'; SELECT TOP 1 object_id FROM sys.all_objects",(e)=>{ if(e){errRaised=true; detail=trunc(e.message);} res(); }); req.on('row',()=>{ rows++; if(!mk){mk=true; marker();} }); c.execSqlBatch(req); });
    console.log(`RESULT midresult-drop errorRaised=${errRaised} rowsRead=${rows} detail=${detail}`); try{c.close();}catch(e){}
  } else if(SC==='pinned-discard'){
    const c=await connect(); await exec(c,'CREATE TABLE #pinme(x int)',true); // batch -> session temp -> pins
    console.log('RESULT pinned-discard pinned=true'); marker();
    process.exit(0); // hard exit drops the socket while pinned
  } else if(SC==='pin-hold'){
    try{ const c=await connect(); await exec(c,'CREATE TABLE #hold(x int)',true); console.log('RESULT pin-hold acquired=true'); await sleep(SLEEP*1000); c.close(); }
    catch(e){ console.log('RESULT pin-hold acquired=false detail='+trunc(e.message)); }
  } else { console.log('RESULT unknown-scenario '+SC); }
 } catch(e){ console.log('RESULT '+SC+' errorRaised=true detail='+trunc(e.message)); }
 process.exit(0);
})();
