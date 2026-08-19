// Drives grid shapes through the proxy, each on its own connection (= one proxy session). tedious's
// execSql() wraps statements in sp_executesql (exec-scoped: a #temp is dropped on return -> poolable),
// while execSqlBatch() sends a raw SQLBatch (session-scoped: a #temp leaks -> pins). Both are captured.
const { Connection, Request, TYPES } = require('tedious');
const cfg = () => ({
  server: process.env.HOST || '127.0.0.1',
  options: { port: +(process.env.PORT || 23433), encrypt: false, trustServerCertificate: true, database: 'master', rowCollectionOnRequestCompletion: true },
  authentication: { type: 'default', options: { userName: process.env.USER || 'sa', password: process.env.PW } },
});
function run(label, sql, { batch = false, params } = {}) {
  return new Promise((resolve) => {
    const c = new Connection(cfg());
    c.on('connect', (err) => {
      if (err) { console.log(`  ${label.padEnd(26)} CONN ERR ${err.message}`); c.close(); return resolve(); }
      const req = new Request(sql, (e) => { console.log(`  ${label.padEnd(26)} ${e ? 'RUN ERR ' + e.message : 'ok'}`); setTimeout(() => c.close(), 150); });
      if (params) params(req);
      if (batch) c.execSqlBatch(req); else c.execSql(req);
    });
    c.on('end', resolve); c.on('error', () => {}); c.connect();
  });
}
(async () => {
  await run('1 plain-select (rpc)', 'SELECT 1');
  await run('2 set-nocount (rpc)', 'SET NOCOUNT ON; SELECT 1');
  await run('3 temp-table (rpc)', 'CREATE TABLE #t(id int); INSERT INTO #t VALUES(1)');
  await run('4 param-query (rpc)', 'SELECT @p1', { params: (r) => r.addParameter('p1', TYPES.Int, 42) });
  await run('5 begin-tran (rpc)', 'BEGIN TRANSACTION; SELECT 1; COMMIT');
  await run('6 temp-table (batch)', 'CREATE TABLE #t(id int); INSERT INTO #t VALUES(1)', { batch: true });
  await run('7 begin-tran-open (batch)', 'BEGIN TRANSACTION; SELECT 1', { batch: true });
})();
