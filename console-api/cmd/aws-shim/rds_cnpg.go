// CloudNativePG operations behind the aws-shim RDS front door (polyhedron#162).
//
// An RDS "DB instance" is a real CloudNativePG (CNPG) Cluster — actual PostgreSQL, so the data path is
// Postgres by construction, not emulation. This file is the thin control layer: create/get/delete the
// Cluster and its master-credential Secret, drive snapshots as CNPG Backups (volumeSnapshot method on
// Longhorn CSI), and restore a Backup into a NEW Cluster. RDS metadata that CNPG does not model (master
// username, instance class, deletion protection, tags, engine) rides as annotations on the Cluster, so the
// Cluster CR is the single source of truth and survives a shim restart.
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
	secretName := "rds-" + p.id + "-master"
	masterSec := secretMasterCred(secretName, r.ns, p.masterUser, p.masterPass)
	if _, err := r.cs.CoreV1().Secrets(r.ns).Create(ctx, &masterSec, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create master secret: %w", err)
	}
	cl := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      p.id,
			"namespace": r.ns,
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
	if _, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).Create(ctx, cl, metav1.CreateOptions{}); err != nil {
		// roll back the secret so a failed create does not orphan a credential
		_ = r.cs.CoreV1().Secrets(r.ns).Delete(ctx, secretName, metav1.DeleteOptions{})
		return err
	}
	return nil
}

// createRestoredInstance provisions a NEW Cluster whose data is recovered from a Backup's volume snapshot.
func (r *rdsCNPG) createRestoredInstance(ctx context.Context, newID, backupName string, src instanceView) error {
	secretName := "rds-" + newID + "-master"
	// The restored instance keeps the source's master credential (AWS restores with the snapshot's users).
	sec, err := r.cs.CoreV1().Secrets(r.ns).Get(ctx, "rds-"+src.id+"-master", metav1.GetOptions{})
	if err == nil {
		dup := secretMasterCred(secretName, r.ns, string(sec.Data["username"]), string(sec.Data["password"]))
		_, _ = r.cs.CoreV1().Secrets(r.ns).Create(ctx, &dup, metav1.CreateOptions{})
	}
	cl := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      newID,
			"namespace": r.ns,
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
	_, err = r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).Create(ctx, cl, metav1.CreateOptions{})
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
	u, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return instanceView{found: false}, nil
		}
		return instanceView{}, err
	}
	return r.viewOf(u), nil
}

func (r *rdsCNPG) listInstances(ctx context.Context) ([]instanceView, error) {
	l, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=aws-shim-rds"})
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
		endpoint:          u.GetName() + "-rw." + r.ns + ".svc.cluster.local",
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
	_, err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).Patch(ctx, id, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

func (r *rdsCNPG) deleteInstance(ctx context.Context, id string) error {
	if err := r.dyn.Resource(cnpgClusterGVR).Namespace(r.ns).Delete(ctx, id, metav1.DeleteOptions{}); err != nil {
		return err
	}
	_ = r.cs.CoreV1().Secrets(r.ns).Delete(ctx, "rds-"+id+"-master", metav1.DeleteOptions{})
	return nil
}

// --- snapshots (CNPG Backups, volumeSnapshot method) ---

func (r *rdsCNPG) createSnapshot(ctx context.Context, snapID, instanceID string) error {
	b := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Backup",
		"metadata": map[string]any{
			"name": snapID, "namespace": r.ns,
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "aws-shim-rds"},
			"annotations": rdsAnnotations(map[string]string{"instance": instanceID}),
		},
		"spec": map[string]any{
			"method":  "volumeSnapshot",
			"cluster": map[string]any{"name": instanceID},
		},
	}}
	_, err := r.dyn.Resource(cnpgBackupGVR).Namespace(r.ns).Create(ctx, b, metav1.CreateOptions{})
	return err
}

type snapshotView struct {
	id, instance, status string
	found                bool
}

func (r *rdsCNPG) getSnapshot(ctx context.Context, id string) (snapshotView, error) {
	u, err := r.dyn.Resource(cnpgBackupGVR).Namespace(r.ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return snapshotView{found: false}, nil
		}
		return snapshotView{}, err
	}
	return r.snapView(u), nil
}

func (r *rdsCNPG) listSnapshots(ctx context.Context) ([]snapshotView, error) {
	l, err := r.dyn.Resource(cnpgBackupGVR).Namespace(r.ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=aws-shim-rds"})
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
	return r.dyn.Resource(cnpgBackupGVR).Namespace(r.ns).Delete(ctx, id, metav1.DeleteOptions{})
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
