package render

import (
	"strings"
	"testing"
)

func backupCtx(spec map[string]any, name string) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"labels": map[string]any{"crossplane.io/claim-name": name, "crossplane.io/claim-namespace": "team-a"},
		},
	}}}}
}

// kind: BackupVault renders a Velero BackupStorageLocation, prefix-isolated in the shared velero bucket,
// and surfaces the BSL name in status.
func TestBackupVault_RendersBSL(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/backupvault-composition.yaml")
	out := render(t, tmpl, backupCtx(map[string]any{"description": "prod db backups"}, "prod"))
	for _, want := range []string{
		"kind: BackupStorageLocation", "apiVersion: velero.io/v1",
		"name: openinfra-vault-prod", "namespace: velero",
		"bucket: velero", "prefix: vaults/prod", // the per-vault isolation
		"s3Url: http://minio.minio.svc.cluster.local:9000",
		"openinfra.dev/backupvault: prod",
		"backupStorageLocation: openinfra-vault-prod", // status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("BackupVault render missing %q; got:\n%s", want, grepCtx(out, "BackupStorageLocation"))
		}
	}
}

// kind: BackupPlan renders one Velero Schedule per rule, each with its cron, TTL (retentionDays*24h) and
// target vault's BSL. The default selection backs up all namespaces minus the system/backup excludes.
func TestBackupPlan_RendersSchedulesDefaultSelection(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/backupplan-composition.yaml")
	out := render(t, tmpl, backupCtx(map[string]any{
		"rules": []any{
			map[string]any{"name": "daily", "schedule": "0 3 * * *", "retentionDays": int64(7), "targetVault": "prod"},
			map[string]any{"name": "weekly", "schedule": "0 4 * * 0", "retentionDays": int64(30), "targetVault": "archive"},
		},
	}, "app-backup"))
	for _, want := range []string{
		"kind: Schedule", "apiVersion: velero.io/v1",
		"name: app-backup-daily", "name: app-backup-weekly",
		`schedule: "0 3 * * *"`, `schedule: "0 4 * * 0"`,
		"ttl: 168h0m0s", // 7 days
		"ttl: 720h0m0s", // 30 days
		"storageLocation: openinfra-vault-prod",
		"storageLocation: openinfra-vault-archive",
		"defaultVolumesToFsBackup: true",
		"openinfra.dev/backupplan: app-backup",
		"scheduleCount: 2", // status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("BackupPlan render missing %q; got:\n%s", want, grepCtx(out, "Schedule"))
		}
	}
	// Default selection: all namespaces, minus the system/backup excludes (never back up the backup store).
	if !strings.Contains(out, `includedNamespaces: ["*"]`) || !strings.Contains(out, "excludedNamespaces: [kube-system, velero, minio]") {
		t.Errorf("default selection must be all-namespaces-minus-system; got:\n%s", grepCtx(out, "Namespaces"))
	}
}

// An explicit selection (namespaces + labels + resource types) is honored verbatim, with no system
// excludes added (the author chose the scope).
func TestBackupPlan_ExplicitSelection(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/backupplan-composition.yaml")
	out := render(t, tmpl, backupCtx(map[string]any{
		"rules": []any{map[string]any{"name": "db", "schedule": "0 2 * * *", "targetVault": "prod"}},
		"selection": map[string]any{
			"includedNamespaces": []any{"team-a", "team-b"},
			"labelSelector":      map[string]any{"app": "payments"},
			"includedResources":  []any{"clusters.postgresql.cnpg.io", "persistentvolumeclaims"},
		},
	}, "db-backup"))
	for _, want := range []string{
		"- \"team-a\"", "- \"team-b\"",
		"matchLabels:", "app: \"payments\"",
		"clusters.postgresql.cnpg.io", "persistentvolumeclaims",
		"ttl: 720h0m0s", // retentionDays unset -> default 30d
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explicit-selection render missing %q; got:\n%s", want, grepCtx(out, "template"))
		}
	}
	// No system excludes when the author set includedNamespaces explicitly.
	if strings.Contains(out, "excludedNamespaces") {
		t.Errorf("explicit includedNamespaces must not add system excludes; got:\n%s", grepCtx(out, "Namespaces"))
	}
}
