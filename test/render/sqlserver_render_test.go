package render

import (
	"strings"
	"testing"
)

// mkSQLServer builds a render context for a kind: Application whose spec.database.engine is sqlserver.
func mkSQLServer(db map[string]any) map[string]any {
	db["engine"] = "sqlserver"
	if db["name"] == nil {
		db["name"] = "estate"
	}
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{"image": "ghcr.io/x/app:latest", "database": db},
		"metadata": map[string]any{"uid": "00000000-0000-0000-0000-0000000000ff", "labels": map[string]any{
			"crossplane.io/claim-name": "myapp", "crossplane.io/claim-namespace": "default"}},
	}}}}
}

// engine=sqlserver WITHOUT acceptEula is fail-closed: it provisions a blocked ConfigMap carrying the
// EULA reason and NOTHING else — no StatefulSet, and crucially no proprietary MSSQL image is pulled.
func TestSQLServer_FailsClosedWithoutEula(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{}))

	for _, want := range []string{
		"sqlserver-blocked",
		`openinfra.dev/blocked: "eula-not-accepted"`,
		"go.microsoft.com/fwlink", // the EULA link
	} {
		if !strings.Contains(out, want) {
			t.Errorf("blocked sqlserver render missing %q; got:\n%s", want, grepCtx(out, "sqlserver"))
		}
	}
	// Fail-closed means: no workload and no image pulled.
	if strings.Contains(out, "mcr.microsoft.com/mssql/server") {
		t.Errorf("without acceptEula the proprietary MSSQL image must NOT be referenced:\n%s", grepCtx(out, "mssql"))
	}
	if strings.Contains(out, "kind: StatefulSet") {
		t.Errorf("without acceptEula no SQL Server StatefulSet may render")
	}
}

// engine=sqlserver WITH acceptEula provisions the real managed engine: a connection Secret, a
// StatefulSet on the Microsoft image with EULA/PID/SA-password env and the uid-10001 perm fix, and a
// TDS Service named <name>-sqlserver (exactly what kind: DatabaseProxy engineFamily: sqlserver fronts).
func TestSQLServer_ProvisionsWhenEulaAccepted(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{"acceptEula": true, "memory": "8Gi"}))

	for _, want := range []string{
		"kind: StatefulSet",
		"name: myapp-sqlserver", // resources are named by the claim (myapp), like <name>-babelfish
		`DATABASE: "estate"`,    // database.name is the target DB inside the instance
		"mcr.microsoft.com/mssql/server:2022-latest",
		`{ name: ACCEPT_EULA, value: "Y" }`,
		`{ name: MSSQL_PID, value: "Developer" }`,
		"name: MSSQL_SA_PASSWORD",
		"securityContext: { fsGroup: 10001 }",
		"chown -R 10001:0 /var/opt/mssql",
		"mountPath: /var/opt/mssql, subPath: mssql",
		`openinfra.dev/non-production: "true"`, // Developer edition is non-prod
		// the connection secret
		"ENGINE: sqlserver",
		"SQLSERVER_URL:",
		// the TDS service the proxy expects
		"{ name: tds, port: 1433, targetPort: 1433 }",
		`memory: "8Gi"`, // database.memory sizes the container
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sqlserver render missing %q; got:\n%s", want, grepCtx(out, "sqlserver"))
		}
	}
	if strings.Contains(out, "sqlserver-blocked") {
		t.Errorf("an accepted sqlserver must NOT render the blocked ConfigMap")
	}
	// The app container gets the connection injected only on the accepted path.
	if !strings.Contains(out, "secretKeyRef: { name: myapp-sqlserver, key: SQLSERVER_URL }") {
		t.Errorf("accepted sqlserver must inject SQLSERVER_URL into the app container; got:\n%s", grepCtx(out, "SQLSERVER_URL"))
	}
}

// restoreFrom wires the .bak landing path: an mc init stages the object, a restore sidecar runs the
// RESTORE script from a ConfigMap, and a shared restore volume carries the .bak to the engine. Absent
// restoreFrom, none of it renders.
func TestSQLServer_RestoreFrom(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)

	// Without restoreFrom: no restore machinery (and no node emptyDir staging — there never is one now).
	plain := render(t, tmpl, mkSQLServer(map[string]any{"acceptEula": true}))
	for _, forbid := range []string{"RESTORE DATABASE", "name: fetch-bak", "sqlserver-restore", "capacity-preflight", "name: restore-stage"} {
		if strings.Contains(plain, forbid) {
			t.Errorf("a non-restoring sqlserver must NOT render %q", forbid)
		}
	}

	// With restoreFrom: the full landing path.
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"restoreFrom": map[string]any{"bucket": "import", "key": "db.bak", "secret": "restore-creds"},
	}))
	for _, want := range []string{
		"name: myapp-sqlserver-restore",                   // the restore-script ConfigMap
		"restore.sh: |",                                   // the script
		"DB='estate'",                                     // target DB name templated into the script
		"RESTORE DATABASE [$DB] FROM DISK",                // the RESTORE (DB resolved at runtime)
		"name: fetch-bak",                                 // the staging init
		"ghcr.io/harn3ss/open-infra-mc",                   // mc stages the .bak
		"src/import/db.bak",                               // from the configured bucket/key
		"secretRef: { name: restore-creds }",              // S3 creds
		`command: ["bash", "/opt/restore/restore.sh"]`,    // the restore sidecar
		"mountPath: /restore, subPath: restore",           // staged on the SIZED data volume, not a node emptyDir
		"test -f /restore/.done",                          // readiness gate: NotReady until the restore completes
		"terminationMessagePolicy: FallbackToLogsOnError", // a failed restore surfaces its reason
	} {
		if !strings.Contains(out, want) {
			t.Errorf("restoring sqlserver render missing %q; got:\n%s", want, grepCtx(out, "restore"))
		}
	}
	// The .bak must NOT be staged to the old node-local emptyDir volume any more (it could fill/evict
	// the node); the restore-stage volume is gone entirely.
	if strings.Contains(out, "name: restore-stage") {
		t.Errorf("restore staging must be on the sized data volume, not the old restore-stage emptyDir; got:\n%s", grepCtx(out, "restore"))
	}
}

// The restore path runs a capacity preflight on the actually-scheduled node that fails fast when the
// requested size can't fit — turning a silent mid-RESTORE ENOSPC into an immediate, explained failure —
// and the restore script reclaims the staged .bak once the database is in place.
func TestSQLServer_RestoreCapacityPreflight(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"size":        "499Gi",
		"restoreFrom": map[string]any{"bucket": "import", "key": "db.bak", "secret": "restore-creds"},
	}))
	for _, want := range []string{
		"name: capacity-preflight",           // the preflight init container
		`NEED='499Gi'`,                       // the requested size is what it checks against
		"INSUFFICIENT STORAGE",               // the actionable failure message
		"fieldPath: spec.nodeName",           // it names the node in the message
		"rm -f \"$BAK\"",                     // the script reclaims the staged .bak after a successful restore
		`mkdir -p /data/mssql /data/restore`, // fix-perms owns the staging subdir for the non-root writer
	} {
		if !strings.Contains(out, want) {
			t.Errorf("restore capacity/staging render missing %q; got:\n%s", want, grepCtx(out, "preflight"))
		}
	}
	// The preflight is restore-only — a fresh DB grows into its size and must not fail at startup.
	fresh := render(t, tmpl, mkSQLServer(map[string]any{"acceptEula": true, "size": "499Gi"}))
	if strings.Contains(fresh, "capacity-preflight") {
		t.Errorf("a fresh (non-restore) sqlserver must not run the restore capacity preflight")
	}
}

// Express edition maps to MSSQL_PID=Express and is NOT labelled non-production; placement renders a
// nodeSelector so a large DB can be pinned to a node with the RAM/storage.
func TestSQLServer_EditionAndPlacement(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula": true,
		"edition":    "Express",
		"placement":  map[string]any{"openinfra.dev/db-host": "mlbox"},
	}))

	if !strings.Contains(out, `{ name: MSSQL_PID, value: "Express" }`) {
		t.Errorf("Express edition must set MSSQL_PID=Express; got:\n%s", grepCtx(out, "MSSQL_PID"))
	}
	if strings.Contains(out, `openinfra.dev/non-production: "true"`) {
		t.Errorf("Express is not flagged non-production")
	}
	if !strings.Contains(out, `openinfra.dev/db-host: "mlbox"`) {
		t.Errorf("placement must render a nodeSelector; got:\n%s", grepCtx(out, "nodeSelector"))
	}
}

//: a STRIPED restore via explicit keys fetches each stripe to db_<i>.bak and restores the
// whole set with one FROM DISK + N DISK clauses, summed-headroom checked before RESTORE. Single-file
// markers must be ABSENT on this path.
func TestSQLServer_RestoreStripedKeys(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"size":        "499Gi",
		"restoreFrom": map[string]any{"bucket": "import", "keys": []any{"backup_1.bak", "backup_2.bak"}, "secret": "restore-creds"},
	}))
	for _, want := range []string{
		`mc cp "src/import/backup_1.bak" "/restore/db_1.bak"`, // stripe 1 → ordered name
		`mc cp "src/import/backup_2.bak" "/restore/db_2.bak"`, // stripe 2
		"for f in /restore/db_*.bak",                         // restore builds the DISK set from the staged stripes
		"RESTORE FILELISTONLY $DISKS",                        // FILELISTONLY across the whole set
		"RESTORE DATABASE [$DB] $DISKS WITH REPLACE",         // multi-DISK restore
		"INSUFFICIENT STORAGE",                               // summed-headroom guard before RESTORE
		"rm -f /restore/db_*.bak",                            // reclaim the whole staged set
		"incomplete stripe set",                              // missing-stripe fails loudly
		"restore already complete — skipping download",       // fetch-bak skips the re-download once restored
	} {
		if !strings.Contains(out, want) {
			t.Errorf("striped(keys) render missing %q; got:\n%s", want, grepCtx(out, "stripe"))
		}
	}
	// The single-file machinery must NOT render on the striped path.
	for _, forbid := range []string{"FROM DISK=N'$BAK'", "/restore/db.bak"} {
		if strings.Contains(out, forbid) {
			t.Errorf("striped(keys) must not render single-file marker %q", forbid)
		}
	}
}

// A STRIPED restore via prefix enumerates every object under the prefix (sorted) and fails closed on zero.
func TestSQLServer_RestoreStripedPrefix(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"restoreFrom": map[string]any{"bucket": "import", "prefix": "backup/", "secret": "restore-creds"},
	}))
	for _, want := range []string{
		`mc find "src/import/backup/" | sort`,           // enumerate the stripe set, deterministic order
		"no objects under prefix backup/",               // zero objects fails closed
		`mc cp "$p" "/restore/db_${i}.bak"`,            // each object → ordered stripe name
		"RESTORE DATABASE [$DB] $DISKS WITH REPLACE",   // multi-DISK restore (shared striped script)
		"restore already complete — skipping download", // fetch-bak skips the re-download once restored
	} {
		if !strings.Contains(out, want) {
			t.Errorf("striped(prefix) render missing %q; got:\n%s", want, grepCtx(out, "prefix"))
		}
	}
	// Regression: `mc find` has NO --type flag (that is GNU find). Passing one makes mc print its help
	// and emit an empty stripe list, so a live prefix restore fails "no objects under prefix". The old
	// test asserted the broken string verbatim, so it passed while the command did not work.
	if strings.Contains(out, "--type f") {
		t.Errorf("striped(prefix) must not pass `--type f` to mc find (not an mc flag; empties the stripe set)")
	}
}

// Ambiguous restoreFrom (more than one of key/keys/prefix) fails the render loudly (fail-closed).
func TestSQLServer_RestoreAmbiguousFails(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	err := renderErr(tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"restoreFrom": map[string]any{"bucket": "import", "key": "a.bak", "keys": []any{"b.bak"}, "secret": "restore-creds"},
	}))
	if err == nil || !strings.Contains(err.Error(), "exactly one of key, keys, or prefix") {
		t.Errorf("ambiguous restoreFrom must fail the render with the exactly-one-of message; got err=%v", err)
	}
	// restoreFrom with a bucket but none of key/keys/prefix is also rejected.
	err2 := renderErr(tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"restoreFrom": map[string]any{"bucket": "import", "secret": "restore-creds"},
	}))
	if err2 == nil || !strings.Contains(err2.Error(), "one of key, keys, or prefix is required") {
		t.Errorf("restoreFrom without a key form must fail; got err=%v", err2)
	}
}

// The sqlserver StatefulSet Object must derive readiness from the workload's readyReplicas, not the
// provider default (ready as soon as the Object is CREATED). Otherwise the XR/claim report Ready while
// the restore sidecar is still restoring (or has failed) — a silently-healthy false green that
// contradicts the restoreFrom contract ("stays NotReady until the restore completes").
func TestSQLServer_ReadinessDerivesFromReplicas(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	out := render(t, tmpl, mkSQLServer(map[string]any{
		"acceptEula":  true,
		"restoreFrom": map[string]any{"bucket": "import", "keys": []any{"a.bak", "b.bak"}, "secret": "restore-creds"},
	}))
	for _, want := range []string{
		"policy: DeriveFromCelQuery",
		"object.status.readyReplicas == object.spec.replicas",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sqlserver StatefulSet readiness missing %q; got:\n%s", want, grepCtx(out, "readiness"))
		}
	}
}
