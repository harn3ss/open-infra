// CloudNativePG operations behind the aws-shim RDS front door.
//
// An RDS "DB instance" is a real CloudNativePG (CNPG) Cluster — actual PostgreSQL, so the data path is
// Postgres by construction, not emulation. This file is the thin control layer: create/get/delete the
// Cluster and its master-credential Secret, drive snapshots as CNPG Backups (volumeSnapshot method on
// Longhorn CSI), and restore a Backup into a NEW Cluster. RDS metadata that CNPG does not model (master
// username, instance class, deletion protection, tags, engine) rides as annotations on the Cluster, so the
// Cluster CR is the single source of truth and survives a shim restart.
//
// Accounts: an account's DB instances and snapshots are kept in its own namespace — the RDS namespace for
// the management account (where they always were), a member account's home for a member's (nsFor) — so
// the same identifier lives in each account independently, each account lists only its own, a snapshot
// restores only within its account, and a member account's database runs inside its account's network
// isolation, out of reach of the management account's grants. A member's home can hold other database
// clusters (a kind: Database's); only the clusters and backups this front door made are its DB instances
// and snapshots there.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	cnpgClusterGVR = schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}
	cnpgBackupGVR  = schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "backups"}
)

const rdsAnnoPrefix = "rds.openinfra.dev/"

// instanceClasses maps AWS DB instance classes to real pod resource requests/limits. An unrecognized
// class is refused (never quietly under-provisioned).
var instanceClasses = map[string]struct{ reqCPU, reqMem, limCPU, limMem string }{
	"db.t3.micro":  {"100m", "256Mi", "500m", "512Mi"},
	"db.t3.small":  {"200m", "512Mi", "1", "1Gi"},
	"db.t3.medium": {"500m", "1Gi", "2", "2Gi"},
	"db.t3.large":  {"1", "2Gi", "2", "4Gi"},
	"db.m5.large":  {"1", "4Gi", "2", "8Gi"},
	"db.m5.xlarge": {"2", "8Gi", "4", "16Gi"},
}

func knownInstanceClass(c string) bool { _, ok := instanceClasses[c]; return ok }

type rdsCNPG struct {
	dyn dynamic.Interface
	cs  kubernetes.Interface
	ns  string
}

// rdsManagedBy is the app.kubernetes.io/managed-by value on every cluster, backup and secret this front
// door makes.
const rdsManagedBy = "aws-shim-rds"

// nsFor is the namespace the caller's account's DB instances and snapshots are kept in: the RDS namespace
// for the management account, a member account's home for a member's.
func (r *rdsCNPG) nsFor(ctx context.Context) string { return accountNamespace(ctx, r.ns) }

// rdsOwned reports whether an object found by name in the caller's account's namespace is one of this
// front door's: in a member account's home, where other database clusters and their backups live (a kind:
// Database's), only an object labelled as the front door's is a DB instance or snapshot. The RDS namespace
// holds the front door's alone, and the management account's lookups are as they always were.
func rdsOwned(ctx context.Context, u *unstructured.Unstructured) bool {
	return !isMemberRequest(ctx) || u.GetLabels()["app.kubernetes.io/managed-by"] == rdsManagedBy
}

// createInstanceParams carries the honored subset of CreateDBInstance.
type createInstanceParams struct {
	id                string
	masterUser        string
	masterPass        string
	dbName            string
	instanceClass     string
	allocatedGB       int
	storageEncrypted  bool
	deletionProtected bool
	tags              map[string]string
}

// createInstance provisions a CNPG Cluster (+ its master-credential Secret) for a new DB instance.
func (r *rdsCNPG) createInstance(ctx context.Context, p createInstanceParams) error {
	// The master credential Secret (basic-auth) — CNPG uses it for the owner role so the caller's
	// MasterUserPassword really is the database password, and it is never generated or returned.
	ns := r.nsFor(ctx)
	secretName := "rds-" + p.id + "-master"
	masterSec := secretMasterCred(secretName, ns, p.masterUser, p.masterPass)
	if _, err := r.cs.CoreV1().Secrets(ns).Create(ctx, &masterSec, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create master secret: %w", err)
	}
	cl := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      p.id,
			"namespace": ns,
			"labels":    map[string]any{"app.kubernetes.io/managed-by": "aws-shim-rds"},
			"annotations": rdsAnnotations(map[string]string{
				"master-username":     p.masterUser,
				"engine":              "postgres",
				"instance-class":      p.instanceClass,
				"allocated-storage":   fmt.Sprintf("%d", p.allocatedGB),
				"storage-encrypted":   boolStr(p.storageEncrypted),
				"deletion-protection": boolStr(p.deletionProtected),
				"db-name":             p.dbName,
				"tags":                encodeTags(p.tags),
			}),
		},
		"spec": map[string]any{
			"instances": int64(1),
			"storage":   map[string]any{"size": fmt.Sprintf("%dGi", p.allocatedGB), "storageClass": "longhorn"},
			"bootstrap": map[string]any{"initdb": map[string]any{
				"database": p.dbName,
				"owner":    p.masterUser,
				"secret":   map[string]any{"name": secretName},
			}},
			"resources": resourcesFor(p.instanceClass),
			// volumeSnapshot backups on the Longhorn CSI snapshot class — this is what makes
			// CreateDBSnapshot/RestoreDBInstanceFromDBSnapshot genuine.
			"backup": map[string]any{"volumeSnapshot": map[string]any{"className": "longhorn-snapshot"}},
		},
	}}
	if _, err := r.dyn.Resource(cnpgClusterGVR).Namespace(ns).Create(ctx, cl, metav1.CreateOptions{}); err != nil {
		// roll back the secret so a failed create does not orphan a credential
		_ = r.cs.CoreV1().Secrets(ns).Delete(ctx, secretName, metav1.DeleteOptions{})
		return err
	}
	return nil
}

// createRestoredInstance provisions a NEW Cluster whose data is recovered from a Backup's volume snapshot.
func (r *rdsCNPG) createRestoredInstance(ctx context.Context, newID, backupName string, src instanceView) error {
	// Within the caller's account: the snapshot, its source instance and the new instance are all its own.
	ns := r.nsFor(ctx)
	secretName := "rds-" + newID + "-master"
	// The restored instance keeps the source's master credential (AWS restores with the snapshot's users).
	sec, err := r.cs.CoreV1().Secrets(ns).Get(ctx, "rds-"+src.id+"-master", metav1.GetOptions{})
	if err == nil {
		dup := secretMasterCred(secretName, ns, string(sec.Data["username"]), string(sec.Data["password"]))
		_, _ = r.cs.CoreV1().Secrets(ns).Create(ctx, &dup, metav1.CreateOptions{})
	}
	cl := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      newID,
			"namespace": ns,
			"labels":    map[string]any{"app.kubernetes.io/managed-by": "aws-shim-rds"},
			"annotations": rdsAnnotations(map[string]string{
				"master-username":     src.masterUser,
				"engine":              "postgres",
				"instance-class":      src.instanceClass,
				"allocated-storage":   fmt.Sprintf("%d", src.allocatedGB),
				"storage-encrypted":   boolStr(src.storageEncrypted),
				"deletion-protection": "false",
				"db-name":             src.dbName,
				"restored-from":       backupName,
			}),
		},
		"spec": map[string]any{
			"instances": int64(1),
			"storage":   map[string]any{"size": fmt.Sprintf("%dGi", src.allocatedGB), "storageClass": "longhorn"},
			"resources": resourcesFor(src.instanceClass),
			"backup":    map[string]any{"volumeSnapshot": map[string]any{"className": "longhorn-snapshot"}},
			// Recover from the volume snapshot(s) the Backup produced.
			"bootstrap":        map[string]any{"recovery": map[string]any{"backup": map[string]any{"name": backupName}}},
			"externalClusters": []any{},
		},
	}}
	_, err = r.dyn.Resource(cnpgClusterGVR).Namespace(ns).Create(ctx, cl, metav1.CreateOptions{})
	return err
}

// instanceView is the RDS-relevant projection of a CNPG Cluster.
type instanceView struct {
	id                string
	status            string // creating | available | modifying | backing-up | deleting | failed
	endpoint          string
	port              int
	masterUser        string
	engine            string
	instanceClass     string
	allocatedGB       int
	storageEncrypted  bool
	deletionProtected bool
	dbName            string
	found             bool
}

func (r *rdsCNPG) getInstance(ctx context.Context, id string) (instanceView, error) {
	u, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.nsFor(ctx)).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return instanceView{found: false}, nil
		}
		return instanceView{}, err
	}
	if !rdsOwned(ctx, u) {
		return instanceView{found: false}, nil // another database cluster of the account's, not a DB instance
	}
	return r.viewOf(u), nil
}

func (r *rdsCNPG) listInstances(ctx context.Context) ([]instanceView, error) {
	l, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.nsFor(ctx)).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=aws-shim-rds"})
	if err != nil {
		return nil, err
	}
	out := make([]instanceView, 0, len(l.Items))
	for i := range l.Items {
		out = append(out, r.viewOf(&l.Items[i]))
	}
	return out, nil
}

func (r *rdsCNPG) viewOf(u *unstructured.Unstructured) instanceView {
	ann := u.GetAnnotations()
	v := instanceView{
		id:                u.GetName(),
		masterUser:        ann[rdsAnnoPrefix+"master-username"],
		engine:            ann[rdsAnnoPrefix+"engine"],
		instanceClass:     ann[rdsAnnoPrefix+"instance-class"],
		allocatedGB:       atoiSafe(ann[rdsAnnoPrefix+"allocated-storage"]),
		storageEncrypted:  ann[rdsAnnoPrefix+"storage-encrypted"] == "true",
		deletionProtected: ann[rdsAnnoPrefix+"deletion-protection"] == "true",
		dbName:            ann[rdsAnnoPrefix+"db-name"],
		port:              5432,
		endpoint:          u.GetName() + "-rw." + strOrDefault(u.GetNamespace(), r.ns) + ".svc.cluster.local",
		found:             true,
	}
	// Map CNPG status to the RDS state machine. `available` means readyInstances >= 1 (it truly accepts
	// connections) AND the cluster is not mid-delete.
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	ready, _, _ := unstructured.NestedInt64(u.Object, "status", "readyInstances")
	switch {
	case u.GetDeletionTimestamp() != nil:
		v.status = "deleting"
	case ready >= 1 && strings.Contains(strings.ToLower(phase), "healthy"):
		v.status = "available"
	case strings.Contains(strings.ToLower(phase), "fail"):
		v.status = "failed"
	default:
		v.status = "creating"
	}
	return v
}

// setDeletionProtection patches the annotation (ModifyDBInstance).
func (r *rdsCNPG) setDeletionProtection(ctx context.Context, id string, on bool) error {
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, rdsAnnoPrefix+"deletion-protection", boolStr(on)))
	_, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.nsFor(ctx)).Patch(ctx, id, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

func (r *rdsCNPG) deleteInstance(ctx context.Context, id string) error {
	ns := r.nsFor(ctx)
	if err := r.dyn.Resource(cnpgClusterGVR).Namespace(ns).Delete(ctx, id, metav1.DeleteOptions{}); err != nil {
		return err
	}
	_ = r.cs.CoreV1().Secrets(ns).Delete(ctx, "rds-"+id+"-master", metav1.DeleteOptions{})
	return nil
}

// --- snapshots (CNPG Backups, volumeSnapshot method) ---

func (r *rdsCNPG) createSnapshot(ctx context.Context, snapID, instanceID string) error {
	ns := r.nsFor(ctx)
	b := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Backup",
		"metadata": map[string]any{
			"name": snapID, "namespace": ns,
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "aws-shim-rds"},
			"annotations": rdsAnnotations(map[string]string{"instance": instanceID}),
		},
		"spec": map[string]any{
			"method":  "volumeSnapshot",
			"cluster": map[string]any{"name": instanceID},
		},
	}}
	_, err := r.dyn.Resource(cnpgBackupGVR).Namespace(ns).Create(ctx, b, metav1.CreateOptions{})
	return err
}

type snapshotView struct {
	id, instance, status string
	found                bool
}

func (r *rdsCNPG) getSnapshot(ctx context.Context, id string) (snapshotView, error) {
	u, err := r.dyn.Resource(cnpgBackupGVR).Namespace(r.nsFor(ctx)).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return snapshotView{found: false}, nil
		}
		return snapshotView{}, err
	}
	if !rdsOwned(ctx, u) {
		return snapshotView{found: false}, nil // another database cluster's backup, not a DB snapshot
	}
	return r.snapView(u), nil
}

func (r *rdsCNPG) listSnapshots(ctx context.Context) ([]snapshotView, error) {
	l, err := r.dyn.Resource(cnpgBackupGVR).Namespace(r.nsFor(ctx)).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=aws-shim-rds"})
	if err != nil {
		return nil, err
	}
	out := make([]snapshotView, 0, len(l.Items))
	for i := range l.Items {
		out = append(out, r.snapView(&l.Items[i]))
	}
	return out, nil
}

func (r *rdsCNPG) snapView(u *unstructured.Unstructured) snapshotView {
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	st := "creating"
	switch strings.ToLower(phase) {
	case "completed":
		st = "available"
	case "failed":
		st = "failed"
	}
	return snapshotView{
		id:       u.GetName(),
		instance: u.GetAnnotations()[rdsAnnoPrefix+"instance"],
		status:   st,
		found:    true,
	}
}

func (r *rdsCNPG) deleteSnapshot(ctx context.Context, id string) error {
	return r.dyn.Resource(cnpgBackupGVR).Namespace(r.nsFor(ctx)).Delete(ctx, id, metav1.DeleteOptions{})
}

// --- helpers ---

func resourcesFor(class string) map[string]any {
	c := instanceClasses[class]
	return map[string]any{
		"requests": map[string]any{"cpu": c.reqCPU, "memory": c.reqMem},
		"limits":   map[string]any{"cpu": c.limCPU, "memory": c.limMem},
	}
}

func rdsAnnotations(kv map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range kv {
		out[rdsAnnoPrefix+k] = v
	}
	return out
}

// secretMasterCred builds the basic-auth Secret CNPG uses for the owner role, so the caller's
// MasterUserPassword genuinely becomes the database password (never generated, never returned).
func secretMasterCred(name, ns, user, pass string) corev1.Secret {
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "aws-shim-rds"},
		},
		Type:       corev1.SecretTypeBasicAuth,
		StringData: map[string]string{"username": user, "password": pass},
	}
}

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }

func encodeTags(t map[string]string) string {
	if len(t) == 0 {
		return ""
	}
	b, _ := json.Marshal(t)
	return string(b)
}

func decodeTags(s string) map[string]string {
	out := map[string]string{}
	if s != "" {
		_ = json.Unmarshal([]byte(s), &out)
	}
	return out
}
