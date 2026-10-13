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
