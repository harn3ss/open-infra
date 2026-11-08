package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// setBackupPhase sets a snapshot's Backup phase, as CloudNativePG reports it.
func setBackupPhase(t *testing.T, h *rdsHandler, ns, id, phase string) {
	t.Helper()
	ctx := context.Background()
	u, err := h.cnpg.dyn.Resource(cnpgBackupGVR).Namespace(ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(u.Object, phase, "status", "phase")
	if _, err := h.cnpg.dyn.Resource(cnpgBackupGVR).Namespace(ns).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// asStored makes a Secret's stringData its data, as the API server stores it (the fake client does not).
func asStored(t *testing.T, h *rdsHandler, ns, name string) {
	t.Helper()
	ctx := context.Background()
	sec, err := h.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	for k, v := range sec.StringData {
		sec.Data[k] = []byte(v)
	}
	sec.StringData = nil
	if _, err := h.cs.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func clusterExists(t *testing.T, h *rdsHandler, ns, id string) bool {
	t.Helper()
	_, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(ns).Get(context.Background(), id, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

// A DB instance's snapshots are Longhorn backups (which outlive the volume), owned by their Backup.
func TestRDS_SnapshotsOutliveTheVolume(t *testing.T) {
	h := rdsAccountsHandler(t)
	if code, body := rdsCall(t, h, mgmtDoorCaller(), createDB("orders")); code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	u, _ := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(rdsTestNS).Get(context.Background(), "orders", metav1.GetOptions{})
	vs, _, _ := unstructured.NestedMap(u.Object, "spec", "backup", "volumeSnapshot")
	if vs["className"] != "longhorn-backup" || vs["snapshotOwnerReference"] != "backup" {
		t.Fatalf("snapshots must be longhorn-backup, owned by their Backup: %v", vs)
	}
}

// DeleteDBInstance with a final snapshot removes the instance only once the snapshot has completed; the
// snapshot then restores with no source instance, its settings and master credential kept with it.
func TestRDS_FinalSnapshotThenRestoreWithoutTheSource(t *testing.T) {
	prevWait := rdsFinalSnapshotWait
	rdsFinalSnapshotWait = 0 // the background finisher stops at once; Describe finishes the delete
	defer func() { rdsFinalSnapshotWait = prevWait }()
	h := rdsAccountsHandler(t)
	mgmt := mgmtDoorCaller()
	if code, body := rdsCall(t, h, mgmt, createDB("orders")); code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	markAvailable(t, h, rdsTestNS, "orders")
	asStored(t, h, rdsTestNS, "rds-orders-master")
	del := url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"orders"}, "FinalDBSnapshotIdentifier": {"orders-final"}}
	if code, body := rdsCall(t, h, mgmt, del); code != http.StatusOK || !strings.Contains(body, "<DBInstanceStatus>deleting</DBInstanceStatus>") {
		t.Fatalf("delete with a final snapshot: %d %s", code, body)
	}
	if !clusterExists(t, h, rdsTestNS, "orders") {
		t.Fatal("the instance must not be removed before its final snapshot completes")
	}
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"orders"}}); !strings.Contains(body, "<DBInstanceStatus>deleting</DBInstanceStatus>") {
		t.Fatalf("a delete waiting for its snapshot is deleting: %s", body)
	}
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"CreateDBSnapshot"}, "DBInstanceIdentifier": {"orders"}, "DBSnapshotIdentifier": {"x"}}); rdsErrCode(body) != "InvalidDBInstanceState" {
		t.Errorf("an instance being deleted takes no new snapshot: %s", body)
	}
	if _, err := h.cs.CoreV1().Secrets(rdsTestNS).Get(context.Background(), snapshotSecretName("orders-final"), metav1.GetOptions{}); err != nil {
		t.Fatalf("the master credential is kept with the snapshot: %v", err)
	}
	asStored(t, h, rdsTestNS, snapshotSecretName("orders-final"))

	setBackupPhase(t, h, rdsTestNS, "orders-final", "completed")
	if code, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"orders"}}); code != http.StatusNotFound || rdsErrCode(body) != "DBInstanceNotFound" {
		t.Fatalf("once the snapshot completed the instance is gone: %d %s", code, body)
	}
	if clusterExists(t, h, rdsTestNS, "orders") {
		t.Fatal("the cluster must be deleted once its final snapshot completed")
	}
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBSnapshots"}, "DBSnapshotIdentifier": {"orders-final"}}); !strings.Contains(body, "<MasterUsername>app</MasterUsername>") ||
		!strings.Contains(body, "<Status>available</Status>") {
		t.Fatalf("the snapshot records its instance: %s", body)
	}

	restore := url.Values{"Action": {"RestoreDBInstanceFromDBSnapshot"}, "DBInstanceIdentifier": {"orders-restored"}, "DBSnapshotIdentifier": {"orders-final"}}
	if code, body := rdsCall(t, h, mgmt, restore); code != http.StatusOK {
		t.Fatalf("restore without the source: %d %s", code, body)
	}
	u, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(rdsTestNS).Get(context.Background(), "orders-restored", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ann := u.GetAnnotations()
	if ann[rdsAnnoPrefix+"master-username"] != "app" || ann[rdsAnnoPrefix+"instance-class"] != "db.t3.micro" {
		t.Fatalf("the restored instance takes the snapshot's settings: %v", ann)
	}
	if b, _, _ := unstructured.NestedString(u.Object, "spec", "bootstrap", "recovery", "backup", "name"); b != "orders-final" {
		t.Fatalf("the restored instance recovers from the snapshot: %q", b)
	}
	sec, err := h.cs.CoreV1().Secrets(rdsTestNS).Get(context.Background(), "rds-orders-restored-master", metav1.GetOptions{})
	if err != nil || sec.StringData["username"] != "app" {
		t.Fatalf("the restored instance keeps the snapshot's master credential: %v", err)
	}

	if code, _ := rdsCall(t, h, mgmt, url.Values{"Action": {"DeleteDBSnapshot"}, "DBSnapshotIdentifier": {"orders-final"}}); code != http.StatusOK {
		t.Fatalf("delete snapshot: %d", code)
	}
	if _, err := h.cs.CoreV1().Secrets(rdsTestNS).Get(context.Background(), snapshotSecretName("orders-final"), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deleting the snapshot deletes the credential kept with it: %v", err)
	}
}

// A final snapshot that fails never takes its instance with it: the instance is kept, no longer deleting.
func TestRDS_FailedFinalSnapshotKeepsTheInstance(t *testing.T) {
	prevWait := rdsFinalSnapshotWait
	rdsFinalSnapshotWait = 0
	defer func() { rdsFinalSnapshotWait = prevWait }()
	h := rdsAccountsHandler(t)
	mgmt := mgmtDoorCaller()
	if code, body := rdsCall(t, h, mgmt, createDB("orders")); code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	markAvailable(t, h, rdsTestNS, "orders")
	rdsCall(t, h, mgmt, url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"orders"}, "FinalDBSnapshotIdentifier": {"orders-final"}})
	setBackupPhase(t, h, rdsTestNS, "orders-final", "failed")
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"orders"}}); !strings.Contains(body, "<DBInstanceStatus>available</DBInstanceStatus>") {
		t.Fatalf("an instance whose final snapshot failed is kept and available: %s", body)
	}
	if !clusterExists(t, h, rdsTestNS, "orders") {
		t.Fatal("the instance must be kept")
	}
	// A second final snapshot under the same identifier is refused, as AWS refuses a duplicate.
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"orders"}, "FinalDBSnapshotIdentifier": {"orders-final"}}); rdsErrCode(body) != "DBSnapshotAlreadyExists" {
		t.Fatalf("a duplicate final snapshot identifier: %s", body)
	}
}
