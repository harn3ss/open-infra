package main

// Each account's RDS DB instances and snapshots are its own: a member account's CloudNativePG clusters,
// master-credential Secrets and backups are kept in its home namespace (the management account's in the
// RDS namespace, exactly where they always were), the same identifier lives in both accounts
// independently, each account lists only its own, DBInstanceArn / DBSnapshotArn carry the caller's
// account, and another database cluster in a member's home (a kind: Database's) is not a DB instance.

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const rdsTestNS = "open-infra-rds"

func rdsAccountsHandler(t *testing.T, seed ...runtime.Object) *rdsHandler {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{cnpgClusterGVR: "ClusterList", cnpgBackupGVR: "BackupList"}, seed...)
	cs := csWithSAR(true)
	h := newRDSHandler(cs, &rdsCNPG{dyn: dyn, cs: cs, ns: rdsTestNS}, "default", awsidentity.Current().AccountID, "us-east-1", discardLogger())
	h.authz = doorAccountsAuthz(t)
	return h
}

// rdsDB is the part of a DBInstance / DBSnapshot an RDS response carries that these tests read.
type rdsDB struct {
	ID      string `xml:"DBInstanceIdentifier"`
	Arn     string `xml:"DBInstanceArn"`
	Address string `xml:"Endpoint>Address"`
	SnapID  string `xml:"DBSnapshotIdentifier"`
	SnapArn string `xml:"DBSnapshotArn"`
}

func rdsCall(t *testing.T, h *rdsHandler, c doorCaller, form url.Values) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode())).WithContext(c.ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.serve(w, r, c.claims, "req-1")
	return w.Code, w.Body.String()
}

// rdsElems reads every DBInstance (or DBSnapshot) element of a response.
func rdsElems(t *testing.T, body, elem string) []rdsDB {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(body))
	var out []rdsDB
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == elem {
			var v rdsDB
			if err := dec.DecodeElement(&v, &se); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
	}
}

func rdsErrCode(body string) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal([]byte(body), &e)
	return e.Code
}

func createDB(id string) url.Values {
	return url.Values{"Action": {"CreateDBInstance"}, "DBInstanceIdentifier": {id}, "Engine": {"postgres"},
		"DBInstanceClass": {"db.t3.micro"}, "MasterUsername": {"app"}, "MasterUserPassword": {"secret-pw"}}
}

// markAvailable makes a DB instance's cluster healthy, as CloudNativePG reports it.
func markAvailable(t *testing.T, h *rdsHandler, ns, id string) {
	t.Helper()
	ctx := context.Background()
	u, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(ns).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(u.Object, "Cluster in healthy state", "status", "phase")
	_ = unstructured.SetNestedField(u.Object, int64(1), "status", "readyInstances")
	if _, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(ns).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestRDSAccounts_InstancesAreEachAccountsOwn(t *testing.T) {
	h := rdsAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID
	ctx := context.Background()

	code, body := rdsCall(t, h, mgmt, createDB("orders"))
	if dbs := rdsElems(t, body, "DBInstance"); code != http.StatusOK || len(dbs) != 1 || dbs[0].Arn != "arn:aws:rds:us-east-1:"+mgmtAcct+":db:orders" {
		t.Fatalf("management create: %d %s", code, body)
	}
	code, body = rdsCall(t, h, member, createDB("orders"))
	if dbs := rdsElems(t, body, "DBInstance"); code != http.StatusOK || len(dbs) != 1 || dbs[0].Arn != "arn:aws:rds:us-east-1:"+testMember+":db:orders" {
		t.Fatalf("member create of the same identifier: %d %s", code, body)
	}
	for _, ns := range []string{rdsTestNS, memberHome} {
		if _, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(ns).Get(ctx, "orders", metav1.GetOptions{}); err != nil {
			t.Errorf("cluster in %s: %v", ns, err)
		}
		if _, err := h.cs.CoreV1().Secrets(ns).Get(ctx, "rds-orders-master", metav1.GetOptions{}); err != nil {
			t.Errorf("master secret in %s: %v", ns, err)
		}
	}
	if code, body := rdsCall(t, h, mgmt, createDB("billing")); code != http.StatusOK {
		t.Fatalf("management create: %d %s", code, body)
	}

	// Each account lists its own alone, each ARN in its account.
	list := url.Values{"Action": {"DescribeDBInstances"}}
	_, body = rdsCall(t, h, member, list)
	if dbs := rdsElems(t, body, "DBInstance"); len(dbs) != 1 || dbs[0].ID != "orders" || dbs[0].Arn != "arn:aws:rds:us-east-1:"+testMember+":db:orders" {
		t.Errorf("the member lists its own instances alone: %s", body)
	}
	_, body = rdsCall(t, h, mgmt, list)
	if dbs := rdsElems(t, body, "DBInstance"); len(dbs) != 2 {
		t.Errorf("the management account lists its own two instances: %s", body)
	}
	// An instance only the management account has is not the member's.
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"billing"}}); rdsErrCode(body) != "DBInstanceNotFound" {
		t.Errorf("a member must not see the management account's instance: %s", body)
	}
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"billing"}, "SkipFinalSnapshot": {"true"}}); rdsErrCode(body) != "DBInstanceNotFound" {
		t.Errorf("a member must not delete the management account's instance: %s", body)
	}

	// The member's endpoint is in its home.
	markAvailable(t, h, memberHome, "orders")
	_, body = rdsCall(t, h, member, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"orders"}})
	if dbs := rdsElems(t, body, "DBInstance"); len(dbs) != 1 || dbs[0].Address != "orders-rw."+memberHome+".svc.cluster.local" {
		t.Errorf("the member's endpoint: %s", body)
	}
	markAvailable(t, h, rdsTestNS, "orders")
	_, body = rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"orders"}})
	if dbs := rdsElems(t, body, "DBInstance"); len(dbs) != 1 || dbs[0].Address != "orders-rw."+rdsTestNS+".svc.cluster.local" {
		t.Errorf("the management account's endpoint is unchanged: %s", body)
	}

	// Deleting the member's instance leaves the management account's of the same identifier.
	if code, body := rdsCall(t, h, member, url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"orders"}, "SkipFinalSnapshot": {"true"}}); code != http.StatusOK {
		t.Fatalf("member delete: %d %s", code, body)
	}
	if _, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(rdsTestNS).Get(ctx, "orders", metav1.GetOptions{}); err != nil {
		t.Error("the management account's instance survives the member's delete")
	}
	if _, err := h.cs.CoreV1().Secrets(rdsTestNS).Get(ctx, "rds-orders-master", metav1.GetOptions{}); err != nil {
		t.Error("the management account's master secret survives the member's delete")
	}
}

// Another database cluster in a member's home — a kind: Database's, not this front door's — is not one of
// its DB instances: not described, not deleted, not listed, and its name is taken.
func TestRDSAccounts_OtherClustersInTheHomeAreNotInstances(t *testing.T) {
	ledger := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1", "kind": "Cluster",
		"metadata": map[string]any{"name": "ledger", "namespace": memberHome},
	}}
	h := rdsAccountsHandler(t, ledger)
	member := memberDoorCaller()
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DescribeDBInstances"}, "DBInstanceIdentifier": {"ledger"}}); rdsErrCode(body) != "DBInstanceNotFound" {
		t.Errorf("another cluster is not a DB instance: %s", body)
	}
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"ledger"}, "SkipFinalSnapshot": {"true"}}); rdsErrCode(body) != "DBInstanceNotFound" {
		t.Errorf("another cluster must not be deleted as a DB instance: %s", body)
	}
	if _, err := h.cnpg.dyn.Resource(cnpgClusterGVR).Namespace(memberHome).Get(context.Background(), "ledger", metav1.GetOptions{}); err != nil {
		t.Fatal("the other cluster survives")
	}
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DescribeDBInstances"}}); len(rdsElems(t, body, "DBInstance")) != 0 {
		t.Errorf("another cluster is not listed: %s", body)
	}
	if code, body := rdsCall(t, h, member, createDB("ledger")); code != http.StatusBadRequest || rdsErrCode(body) != "DBInstanceAlreadyExists" {
		t.Errorf("a name another cluster holds: %d %s", code, body)
	}
	if _, err := h.cs.CoreV1().Secrets(memberHome).Get(context.Background(), "rds-ledger-master", metav1.GetOptions{}); err == nil {
		t.Error("a refused create leaves no master secret behind")
	}
}

func TestRDSAccounts_SnapshotsAreEachAccountsOwn(t *testing.T) {
	h := rdsAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID
	for _, c := range []struct {
		caller doorCaller
		ns     string
	}{{mgmt, rdsTestNS}, {member, memberHome}} {
		if code, body := rdsCall(t, h, c.caller, createDB("orders")); code != http.StatusOK {
			t.Fatalf("create in %s: %d %s", c.ns, code, body)
		}
		markAvailable(t, h, c.ns, "orders")
	}
	snap := url.Values{"Action": {"CreateDBSnapshot"}, "DBInstanceIdentifier": {"orders"}, "DBSnapshotIdentifier": {"nightly"}}
	_, body := rdsCall(t, h, member, snap)
	if s := rdsElems(t, body, "DBSnapshot"); len(s) != 1 || s[0].SnapArn != "arn:aws:rds:us-east-1:"+testMember+":snapshot:nightly" {
		t.Fatalf("member snapshot: %s", body)
	}
	if _, err := h.cnpg.dyn.Resource(cnpgBackupGVR).Namespace(memberHome).Get(context.Background(), "nightly", metav1.GetOptions{}); err != nil {
		t.Fatalf("the member's snapshot is kept in its home: %v", err)
	}
	if code, body := rdsCall(t, h, mgmt, url.Values{"Action": {"CreateDBSnapshot"}, "DBInstanceIdentifier": {"orders"}, "DBSnapshotIdentifier": {"weekly"}}); code != http.StatusOK ||
		rdsElems(t, body, "DBSnapshot")[0].SnapArn != "arn:aws:rds:us-east-1:"+mgmtAcct+":snapshot:weekly" {
		t.Fatalf("management snapshot: %d %s", code, body)
	}
	idsOf := func(body string) []string {
		var s []string
		for _, e := range rdsElems(t, body, "DBSnapshot") {
			s = append(s, e.SnapID)
		}
		return s
	}
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DescribeDBSnapshots"}}); strings.Join(idsOf(body), ",") != "nightly" {
		t.Errorf("the member lists its own snapshots alone: %s", body)
	}
	if _, body := rdsCall(t, h, mgmt, url.Values{"Action": {"DescribeDBSnapshots"}}); strings.Join(idsOf(body), ",") != "weekly" {
		t.Errorf("the management account lists its own snapshots alone: %s", body)
	}
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"DeleteDBSnapshot"}, "DBSnapshotIdentifier": {"weekly"}}); rdsErrCode(body) != "DBSnapshotNotFound" {
		t.Errorf("a member must not delete the management account's snapshot: %s", body)
	}
	// A restore reads a snapshot of the caller's own account only.
	if _, body := rdsCall(t, h, member, url.Values{"Action": {"RestoreDBInstanceFromDBSnapshot"}, "DBInstanceIdentifier": {"copy"},
		"DBSnapshotIdentifier": {"weekly"}}); rdsErrCode(body) != "DBSnapshotNotFound" {
		t.Errorf("a member must not restore the management account's snapshot: %s", body)
	}
}

func TestRDSAccounts_DoorIsAccountScoped(t *testing.T) {
	if !accountScopedServices["rds"] {
		t.Fatal("rds must be registered as account-scoped")
	}
}
