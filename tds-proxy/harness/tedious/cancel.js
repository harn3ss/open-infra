// Cancel test: start an 8s WAITFOR, cancel at 1.2s. If the proxy forwards the ATTENTION promptly, the
// request returns ~1.2s (canceled); if the cancel is stuck behind the response, it returns ~8s.
const { Connection, Request } = require('tedious');
const cfg = {
  server: process.env.HOST, options: { port: +process.env.PORT, encrypt: false, trustServerCertificate: true, database: 'master' },
  authentication: { type: 'default', options: { userName: process.env.USER, password: process.env.PW } },
};
const c = new Connection(cfg);
c.on('connect', (err) => {
  if (err) { console.log('CONN ERR', err.message); process.exit(1); }
  const t0 = Date.now();
  const req = new Request("WAITFOR DELAY '00:00:08'; SELECT 1", (e) => {
    const ms = Date.now() - t0;
    console.log(`  request returned after ${ms}ms (err=${e && e.message})`);
    console.log(`  VERDICT: ${ms < 3000 ? 'CANCEL WORKS (prompt)' : 'CANCEL BROKEN (waited for the query)'}`);
    c.close(); process.exit(0);
  });
  c.execSqlBatch(req);
  setTimeout(() => { console.log('  -> cancelling at 1.2s'); c.cancel(); }, 1200);
});
c.on('error', () => {});
c.connect();
