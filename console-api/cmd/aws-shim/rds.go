// RDS front door for the aws-shim.
//
// RDS is a different SHAPE from the other doorways: the AWS SDK touches only the CONTROL plane
// (CreateDBInstance / DescribeDBInstances / CreateDBSnapshot); once an instance exists, applications
// connect over the native Postgres wire protocol with a normal driver and the SDK is out of the picture.
// So there is no data-plane emulation: an RDS instance is a real CloudNativePG Postgres (rds_cnpg.go), and
// "is this a real Postgres?" is answered by construction, not emulation.
//
// Wire protocol: AWS query protocol (form-encoded request, XML response) — the SNS/STS family. Errors are
// XML with an <Error><Code>. Authorization is the SAME one policy world as the other front doors (coarse
// impersonated SubjectAccessReview on applications + fine-grained Cedar rds:*), with the shim's own SA
// holding the CNPG-management RBAC. The genuinely-out-of-band part is stated plainly in docs: once a caller
// has the endpoint + credentials they connect straight to Postgres, and IN-DATABASE authorization is
// Postgres's own roles/grants — the Cedar policy world does not sit in that path (equally true of real RDS).
//
// Engine: PostgreSQL only. A non-postgres Engine is refused, never quietly given a Postgres. Honored
// capability flags: DBInstanceClass (mapped to real resources; unknown classes refused), AllocatedStorage,
// EngineVersion (an exact image; versions it does not run are refused), DeletionProtection,
// SkipFinalSnapshot + FinalDBSnapshotIdentifier, and real snapshots/restore (CNPG volumeSnapshot).
// ModifyDBInstance applies each parameter it takes — class, storage growth, the master password,
// deletion protection — and refuses any other, never accepting one it does not apply (#377);
// RebootDBInstance restarts the instance. Refused: StorageEncrypted (no per-volume encryption on this path
// yet), MultiAZ, read replicas, point-in-time recovery, automated backups (BackupRetentionPeriod), a port
// other than 5432, ManageMasterUserPassword, custom parameter/subnet/security groups. See docs/aws-shim.md.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

// RDS keeps each account's DB instances and snapshots apart: a member account's are kept in its home
// namespace (rds_cnpg.go), the management account's in the RDS namespace as always, and their ARNs carry
// the caller's account.
func init() { accountScopedServices["rds"] = true }

const rdsXMLNamespace = "http://rds.amazonaws.com/doc/2014-10-31/"
const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// dbIdentifierRE is the AWS DB identifier shape — and also a valid CNPG Cluster name (RFC-1123 label):
// starts with a letter, lowercase alnum or hyphens, no trailing hyphen, 1-63 chars.
var dbIdentifierRE = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

type rdsHandler struct {
	cs      kubernetes.Interface
	cnpg    *rdsCNPG // nil => provisioning backend not configured (honest error)
	authzNS string
	account string
	region  string
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
}

// arnAccount is the account of the request's ARNs: the install's for the management account, the member
// account's for a member's.
func (h *rdsHandler) arnAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return h.account
	}
	return callerAccount(ctx)
}

// instanceArn is a DB instance's ARN (DBInstanceArn), arn:aws:rds:<region>:<account>:db:<id>, in the
// caller's account; snapshotArn a DB snapshot's (DBSnapshotArn), arn:aws:rds:<region>:<account>:snapshot:<id>.
func (h *rdsHandler) instanceArn(ctx context.Context, id string) string {
	return "arn:aws:rds:" + h.region + ":" + h.arnAccount(ctx) + ":db:" + id
}
func (h *rdsHandler) snapshotArn(ctx context.Context, id string) string {
	return "arn:aws:rds:" + h.region + ":" + h.arnAccount(ctx) + ":snapshot:" + id
}

func newRDSHandler(cs kubernetes.Interface, cnpg *rdsCNPG, authzNS, account, region string, logger *slog.Logger) *rdsHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &rdsHandler{cs: cs, cnpg: cnpg, authzNS: authzNS, account: account, region: region, logger: logger}
}

func (h *rdsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", rdsXMLNamespace)
}

func verbForRDSOp(op string) (string, bool) {
	switch op {
	case "DescribeDBInstances", "DescribeDBSnapshots", "ListTagsForResource":
		return "get", true
	case "CreateDBInstance", "ModifyDBInstance", "RebootDBInstance", "CreateDBSnapshot", "RestoreDBInstanceFromDBSnapshot",
		"AddTagsToResource", "CreateDBInstanceReadReplica", "RestoreDBInstanceToPointInTime":
		return "create", true
	case "DeleteDBInstance", "DeleteDBSnapshot":
		return "delete", true
	}
	return "", false
}

// rdsCheck is one authorization an RDS request needs: an AWS action on an instance or a snapshot.
type rdsCheck struct{ verb, action, resType, id string }

// rdsChecks are the resources an op is authorized on, as AWS authorizes them: an instance is
// DBInstance::<id> (arn:...:db:<id>), a snapshot DBSnapshot::<id> (arn:...:snapshot:<id>).
// CreateDBSnapshot needs the action on the instance and on the snapshot it makes;
// RestoreDBInstanceFromDBSnapshot on the instance it makes and on the snapshot it reads; a
// DeleteDBInstance that takes a final snapshot also needs rds:CreateDBSnapshot on that snapshot.
func rdsChecks(op, verb string, r *http.Request) []rdsCheck {
	inst, snap := r.PostFormValue("DBInstanceIdentifier"), r.PostFormValue("DBSnapshotIdentifier")
	action := "rds:" + op
	switch op {
	case "CreateDBSnapshot", "RestoreDBInstanceFromDBSnapshot":
		return []rdsCheck{{verb, action, "DBInstance", inst}, {verb, action, "DBSnapshot", snap}}
	case "DeleteDBSnapshot":
		return []rdsCheck{{verb, action, "DBSnapshot", snap}}
	case "DescribeDBSnapshots":
		if snap != "" || inst == "" {
			return []rdsCheck{{verb, action, "DBSnapshot", snap}}
		}
	case "DeleteDBInstance":
		checks := []rdsCheck{{verb, action, "DBInstance", inst}}
		if final := r.PostFormValue("FinalDBSnapshotIdentifier"); final != "" && !boolForm(r, "SkipFinalSnapshot") {
			createVerb, _ := verbForRDSOp("CreateDBSnapshot")
			checks = append(checks, rdsCheck{createVerb, "rds:CreateDBSnapshot", "DBSnapshot", final})
		}
		return checks
	}
	return []rdsCheck{{verb, action, "DBInstance", inst}}
}

func (h *rdsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	_ = r.ParseForm()
	op := r.PostFormValue("Action")
	if op == "" {
		op = r.URL.Query().Get("Action")
	}
	verb, known := verbForRDSOp(op)
	if !known {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"The RDS action '"+op+"' is not implemented by this open-infra shim.", rdsXMLNamespace)
		return
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	// Coarse gate, then the fine-grained check, on every instance and snapshot the op touches (rdsChecks);
	// an assumed role is checked on every op (an op naming no identifier on <Type>::*).
	for _, c := range rdsChecks(op, verb, r) {
		if ok, reason := decide(ctx, r, h.authz, claims, c.action, c.resType, c.id,
			coarseThenDataPlane(ctx, r, h.cs, h.authz, claims, c.verb, "openinfra.dev", "applications", h.authzNS, c.id,
				c.action, c.resType, c.id)); !ok {
			h.audit(ctx, op, c.id, "deny", reason)
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, rdsXMLNamespace)
			return
		}
	}
	if h.cnpg == nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID,
			"the RDS provisioning backend (CloudNativePG) is not configured on this shim", rdsXMLNamespace)
		return
	}

	switch op {
	case "CreateDBInstance":
		h.createDBInstance(ctx, w, r, requestID)
	case "DescribeDBInstances":
		h.describeDBInstances(ctx, w, r, requestID)
	case "ModifyDBInstance":
		h.modifyDBInstance(ctx, w, r, requestID)
	case "RebootDBInstance":
		h.rebootDBInstance(ctx, w, r, requestID)
	case "DeleteDBInstance":
		h.deleteDBInstance(ctx, w, r, requestID)
	case "CreateDBSnapshot":
		h.createDBSnapshot(ctx, w, r, requestID)
	case "DescribeDBSnapshots":
		h.describeDBSnapshots(ctx, w, r, requestID)
	case "DeleteDBSnapshot":
		h.deleteDBSnapshot(ctx, w, r, requestID)
	case "RestoreDBInstanceFromDBSnapshot":
		h.restoreFromSnapshot(ctx, w, r, requestID)
	case "CreateDBInstanceReadReplica":
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"read replicas are not supported by the open-infra shim; a rule reporting a replica that does not stream would be a false green.", rdsXMLNamespace)
	case "RestoreDBInstanceToPointInTime":
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"point-in-time recovery is not implemented; use CreateDBSnapshot + RestoreDBInstanceFromDBSnapshot. (DescribeDBInstances does not report a LatestRestorableTime that cannot be honored.)", rdsXMLNamespace)
	case "AddTagsToResource", "ListTagsForResource", "RemoveTagsFromResource":
		// Recognized, authorized and refused: RDS resource tags are not kept yet (#371).
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"RDS "+op+" is recognized but not implemented by the open-infra shim: resource tags are not kept yet.", rdsXMLNamespace)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"RDS "+op+" is recognized but not implemented by the open-infra shim.", rdsXMLNamespace)
	}
}

// --- instances ---

func (h *rdsHandler) createDBInstance(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBInstanceIdentifier")
	if !dbIdentifierRE.MatchString(id) {
		h.paramErr(w, requestID, "DBInstanceIdentifier must be 1-63 chars, lowercase alnum or hyphens, starting with a letter.")
		return
	}
	engine := strings.ToLower(r.PostFormValue("Engine"))
	if engine != "postgres" {
		h.paramErr(w, requestID, "Engine '"+r.PostFormValue("Engine")+"' is not supported; the open-infra shim provisions PostgreSQL only (Engine=postgres).")
		return
	}
	if boolForm(r, "MultiAZ") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"MultiAZ is not supported on this deployment (a single failure domain cannot provide multi-AZ durability); requesting it would be a false green.", rdsXMLNamespace)
		return
	}
	if boolForm(r, "StorageEncrypted") {
		// Genuine at-rest encryption needs per-volume LUKS key provisioning (and key propagation across
		// snapshot/restore) that the RDS path does not yet wire; rather than report StorageEncrypted=true
		// over storage that is not genuinely encrypted (a compliance false green), refuse it in v1.
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"StorageEncrypted is not supported by the open-infra shim RDS front door in v1; omit it (a claimed-but-absent encryption flag would be a compliance false green).", rdsXMLNamespace)
		return
	}
	class := r.PostFormValue("DBInstanceClass")
	if !knownInstanceClass(class) {
		h.paramErr(w, requestID, "DBInstanceClass '"+class+"' is not recognized; provisioning an unrecognized class would be a capacity surprise. Known: db.t3.micro/small/medium/large, db.m5.large/xlarge.")
		return
	}
	user := r.PostFormValue("MasterUsername")
	pass := r.PostFormValue("MasterUserPassword")
	if user == "" || pass == "" {
		h.paramErr(w, requestID, "MasterUsername and MasterUserPassword are required.")
		return
	}
	storage := atoiSafe(r.PostFormValue("AllocatedStorage"))
	if storage < 1 {
		storage = 20
	}
	dbName := r.PostFormValue("DBName")
	if dbName == "" {
		dbName = "app"
	}
	if pg := r.PostFormValue("DBParameterGroupName"); pg != "" && pg != "default.postgres" && !strings.HasPrefix(pg, "default") {
		h.paramErr(w, requestID, "custom DBParameterGroup is not supported in v1; omit it (a silently-ignored parameter group is a false green).")
		return
	}
	version, ok := rdsEngineVersion(r.PostFormValue("EngineVersion"))
	if !ok {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"Cannot find version "+r.PostFormValue("EngineVersion")+" for postgres (this deployment runs PostgreSQL "+rdsDefaultEngineVersion+").", rdsXMLNamespace)
		return
	}
	if e := rdsUnsupportedSettings(r); e != "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, e, rdsXMLNamespace)
		return
	}
	// Existence check.
	if v, err := h.cnpg.getInstance(ctx, id); err != nil {
		h.internal(w, requestID, err)
		return
	} else if v.found {
		writeQueryError(w, http.StatusBadRequest, "DBInstanceAlreadyExists", requestID, "DB instance "+id+" already exists.", rdsXMLNamespace)
		return
	}
	p := createInstanceParams{
		id: id, masterUser: user, masterPass: pass, dbName: dbName,
		instanceClass: class, allocatedGB: storage,
		storageEncrypted:  false, // refused above; storage is plain longhorn in v1
		deletionProtected: boolForm(r, "DeletionProtection"),
		tags:              tagsFromForm(r),
		engineVersion:     version,
	}
	if err := h.cnpg.createInstance(ctx, p); err != nil {
		if isMemberRequest(ctx) && apierrors.IsAlreadyExists(err) {
			// The name is held in the account's home by another of its database clusters (a kind: Database).
			writeQueryError(w, http.StatusBadRequest, "DBInstanceAlreadyExists", requestID, "DB instance "+id+" already exists.", rdsXMLNamespace)
			return
		}
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateDBInstance", id, "allow", "")
	// Return the freshly-created instance in `creating` state (no Endpoint yet — AWS behavior).
	v, _ := h.cnpg.getInstance(ctx, id)
	h.writeInstanceResponse(ctx, w, requestID, "CreateDBInstance", v)
}

func (h *rdsHandler) describeDBInstances(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBInstanceIdentifier")
	var views []instanceView
	if id != "" {
		v, err := h.cnpg.getInstance(ctx, id)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !v.found {
			writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+id+" not found.", rdsXMLNamespace)
			return
		}
		views = []instanceView{v}
	} else {
		var err error
		if views, err = h.cnpg.listInstances(ctx); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	var sb strings.Builder
	sb.WriteString("<DescribeDBInstancesResult><DBInstances>")
	for _, v := range views {
		// A delete waiting for its final snapshot is finished here if the shim restarted meanwhile.
		if v.awaitingSnapshot != "" {
			if waiting, err := h.cnpg.finishDelete(ctx, h.cnpg.nsFor(ctx), v.id); err == nil && !waiting {
				if nv, err := h.cnpg.getInstance(ctx, v.id); err == nil {
					if !nv.found {
						if id != "" {
							writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+id+" not found.", rdsXMLNamespace)
							return
						}
						continue
					}
					v = nv
				}
			}
		}
		sb.WriteString(dbInstanceXML(v, h.instanceArn(ctx, v.id)))
	}
	sb.WriteString("</DBInstances></DescribeDBInstancesResult>")
	h.writeXML(w, requestID, "DescribeDBInstances", sb.String())
}

// rdsModifyParams are the ModifyDBInstance parameters this front door applies; any other is refused.
var rdsModifyParams = map[string]bool{
	"Action": true, "Version": true, "DBInstanceIdentifier": true, "ApplyImmediately": true,
	"DeletionProtection": true, "DBInstanceClass": true, "AllocatedStorage": true, "MasterUserPassword": true,
	"EngineVersion": true, "MultiAZ": true, "BackupRetentionPeriod": true, "DBPortNumber": true,
	"ManageMasterUserPassword": true,
}

// rdsUnsupportedSettings refuses a setting this front door does not provide, on create or modify: a port
// other than PostgreSQL's 5432, automated backups, and a master password kept in Secrets Manager. ""
// when every one asked for is provided.
func rdsUnsupportedSettings(r *http.Request) string {
	for _, k := range []string{"Port", "DBPortNumber"} {
		if p := r.PostFormValue(k); p != "" && p != "5432" {
			return k + " " + p + " is not supported: a DB instance listens on 5432."
		}
	}
	if n := r.PostFormValue("BackupRetentionPeriod"); n != "" && n != "0" {
		return "BackupRetentionPeriod " + n + " is not supported: automated backups are not kept yet; set 0 and use CreateDBSnapshot."
	}
	if boolForm(r, "ManageMasterUserPassword") {
		return "ManageMasterUserPassword is not supported yet: set MasterUserPassword."
	}
	return ""
}

// modifyDBInstance applies each parameter it takes, immediately (as ApplyImmediately does), and refuses any
// other: nothing is accepted and left unapplied (#377).
func (h *rdsHandler) modifyDBInstance(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBInstanceIdentifier")
	for k := range r.PostForm {
		if !rdsModifyParams[k] && !strings.HasPrefix(k, "Tags.") {
			writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
				"ModifyDBInstance "+k+" is not supported by the open-infra RDS front door.", rdsXMLNamespace)
			return
		}
		if strings.HasPrefix(k, "Tags.") {
			writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
				"ModifyDBInstance takes no tags: use AddTagsToResource.", rdsXMLNamespace)
			return
		}
	}
	v, err := h.cnpg.getInstance(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !v.found {
		writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+id+" not found.", rdsXMLNamespace)
		return
	}
	if e := rdsUnsupportedSettings(r); e != "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, e, rdsXMLNamespace)
		return
	}
	if boolForm(r, "MultiAZ") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"MultiAZ is not supported on this deployment (a single failure domain cannot provide multi-AZ durability).", rdsXMLNamespace)
		return
	}
	if ev := r.PostFormValue("EngineVersion"); ev != "" {
		if want, ok := rdsEngineVersion(ev); !ok || want != v.engineVersion {
			writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
				"Upgrading the engine version is not supported yet: DB instance "+id+" runs PostgreSQL "+v.engineVersion+".", rdsXMLNamespace)
			return
		}
	}
	var change instanceChange
	if c := r.PostFormValue("DBInstanceClass"); c != "" && c != v.instanceClass {
		if !knownInstanceClass(c) {
			h.paramErr(w, requestID, "DBInstanceClass '"+c+"' is not recognized. Known: db.t3.micro/small/medium/large, db.m5.large/xlarge.")
			return
		}
		change.instanceClass = c
	}
	if s := r.PostFormValue("AllocatedStorage"); s != "" {
		n, err := strconv.Atoi(s)
		switch {
		case err != nil || n < 1:
			h.paramErr(w, requestID, "AllocatedStorage must be a number of GiB.")
			return
		case n < v.allocatedGB:
			writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
				"Invalid storage size for engine name postgres: "+s+" (storage can only grow; it is "+itoa(v.allocatedGB)+" GiB).", rdsXMLNamespace)
			return
		case n > v.allocatedGB:
			change.allocatedGB = n
		}
	}
	if v.status != "available" && (change.instanceClass != "" || change.allocatedGB > 0 || r.PostFormValue("MasterUserPassword") != "") {
		writeQueryError(w, http.StatusBadRequest, "InvalidDBInstanceState", requestID, "DB instance "+id+" is not available (status "+v.status+").", rdsXMLNamespace)
		return
	}
	if pass := r.PostFormValue("MasterUserPassword"); pass != "" {
		if err := h.cnpg.setMasterPassword(ctx, id, v.masterUser, pass); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	if change.instanceClass != "" || change.allocatedGB > 0 {
		if err := h.cnpg.modifyInstance(ctx, id, change); err != nil {
			h.internal(w, requestID, err)
			return
		}
		if change.instanceClass != "" {
			v.instanceClass = change.instanceClass
		}
		if change.allocatedGB > 0 {
			v.allocatedGB = change.allocatedGB
		}
		v.status = "modifying"
	}
	if r.PostFormValue("DeletionProtection") != "" {
		on := boolForm(r, "DeletionProtection")
		if err := h.cnpg.setDeletionProtection(ctx, id, on); err != nil {
			h.internal(w, requestID, err)
			return
		}
		v.deletionProtected = on
	}
	h.audit(ctx, "ModifyDBInstance", id, "allow", "")
	h.writeInstanceResponse(ctx, w, requestID, "ModifyDBInstance", v)
}

// rebootDBInstance restarts the instance (RebootDBInstance). There is no standby to fail over to.
func (h *rdsHandler) rebootDBInstance(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBInstanceIdentifier")
	if boolForm(r, "ForceFailover") {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"ForceFailover is not supported: DB instance "+id+" has no standby (MultiAZ is not supported).", rdsXMLNamespace)
		return
	}
	v, err := h.cnpg.getInstance(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !v.found {
		writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+id+" not found.", rdsXMLNamespace)
		return
	}
	if v.status != "available" {
		writeQueryError(w, http.StatusBadRequest, "InvalidDBInstanceState", requestID, "DB instance "+id+" is not available (status "+v.status+").", rdsXMLNamespace)
		return
	}
	if err := h.cnpg.modifyInstance(ctx, id, instanceChange{reboot: true}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	v.status = "rebooting"
	h.audit(ctx, "RebootDBInstance", id, "allow", "")
	h.writeInstanceResponse(ctx, w, requestID, "RebootDBInstance", v)
}

func (h *rdsHandler) deleteDBInstance(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBInstanceIdentifier")
	v, err := h.cnpg.getInstance(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !v.found {
		writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+id+" not found.", rdsXMLNamespace)
		return
	}
	if v.deletionProtected {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
			"Cannot delete DB instance "+id+" because deletion protection is enabled. Disable it with ModifyDBInstance first.", rdsXMLNamespace)
		return
	}
	if v.awaitingSnapshot != "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidDBInstanceState", requestID, "DB instance "+id+" is already being deleted.", rdsXMLNamespace)
		return
	}
	// Final snapshot safeguard: SkipFinalSnapshot defaults to false, which REQUIRES a
	// FinalDBSnapshotIdentifier. The instance is removed only once that snapshot has completed, as RDS
	// takes the final snapshot before it deletes (#390): it is marked and answers "deleting" meanwhile.
	skip := boolForm(r, "SkipFinalSnapshot")
	if !skip {
		final := r.PostFormValue("FinalDBSnapshotIdentifier")
		if final == "" {
			writeQueryError(w, http.StatusBadRequest, "InvalidParameterCombination", requestID,
				"FinalDBSnapshotIdentifier is required unless SkipFinalSnapshot is true.", rdsXMLNamespace)
			return
		}
		if !dbIdentifierRE.MatchString(final) {
			h.paramErr(w, requestID, "FinalDBSnapshotIdentifier must be 1-63 chars, lowercase alnum or hyphens, starting with a letter.")
			return
		}
		if ex, err := h.cnpg.getSnapshot(ctx, final); err == nil && ex.found {
			writeQueryError(w, http.StatusBadRequest, "DBSnapshotAlreadyExists", requestID, "Cannot create the snapshot because a snapshot with the identifier "+final+" already exists.", rdsXMLNamespace)
			return
		}
		if err := h.cnpg.createSnapshot(ctx, final, v); err != nil {
			h.internal(w, requestID, err)
			return
		}
		h.audit(ctx, "CreateDBSnapshot", final, "allow", "final snapshot for "+id)
		if err := h.cnpg.markDeleteAfterSnapshot(ctx, id, final); err != nil {
			h.internal(w, requestID, err)
			return
		}
		go h.finishDeleteLater(h.cnpg.nsFor(ctx), id)
	} else if err := h.cnpg.deleteInstance(ctx, id); err != nil {
		h.internal(w, requestID, err)
		return
	}
	v.status = "deleting"
	h.audit(ctx, "DeleteDBInstance", id, "allow", "")
	h.writeInstanceResponse(ctx, w, requestID, "DeleteDBInstance", v)
}

// rdsFinalSnapshotWait bounds how long a delete waits for its final snapshot in the background; a delete
// still waiting then is finished by the next DescribeDBInstances that sees it.
var rdsFinalSnapshotWait, rdsFinalSnapshotPoll = 2 * time.Hour, 10 * time.Second

// finishDeleteLater removes instance ns/id once its final snapshot has completed (finishDelete).
func (h *rdsHandler) finishDeleteLater(ns, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), rdsFinalSnapshotWait)
	defer cancel()
	t := time.NewTicker(rdsFinalSnapshotPoll)
	defer t.Stop()
	for {
		waiting, err := h.cnpg.finishDelete(ctx, ns, id)
		if err != nil && h.logger != nil {
			h.logger.Warn("rds: finishing a delete after its final snapshot", "instance", id, "error", err.Error())
		}
		if !waiting {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *rdsHandler) restoreFromSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	newID := r.PostFormValue("DBInstanceIdentifier")
	snapID := r.PostFormValue("DBSnapshotIdentifier")
	if !dbIdentifierRE.MatchString(newID) {
		h.paramErr(w, requestID, "DBInstanceIdentifier must be 1-63 chars, lowercase alnum or hyphens, starting with a letter.")
		return
	}
	snap, err := h.cnpg.getSnapshot(ctx, snapID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !snap.found {
		writeQueryError(w, http.StatusNotFound, "DBSnapshotNotFound", requestID, "DB snapshot "+snapID+" not found.", rdsXMLNamespace)
		return
	}
	if snap.status != "available" {
		writeQueryError(w, http.StatusBadRequest, "InvalidDBSnapshotState", requestID, "Snapshot "+snapID+" is not yet available (status "+snap.status+").", rdsXMLNamespace)
		return
	}
	// The instance as the snapshot recorded it, so a final snapshot restores after its instance is gone; a
	// snapshot taken before settings were recorded reads them from its source instance.
	src := snap.source
	if !src.found {
		var err error
		if src, err = h.cnpg.getInstance(ctx, snap.instance); err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !src.found {
			writeQueryError(w, http.StatusBadRequest, "InvalidDBSnapshotState", requestID,
				"DB snapshot "+snapID+" does not record its instance's settings, and its source instance no longer exists.", rdsXMLNamespace)
			return
		}
	}
	if c := r.PostFormValue("DBInstanceClass"); c != "" {
		if !knownInstanceClass(c) {
			h.paramErr(w, requestID, "DBInstanceClass "+c+" is not one this front door provisions.")
			return
		}
		src.instanceClass = c
	}
	if ex, _ := h.cnpg.getInstance(ctx, newID); ex.found {
		writeQueryError(w, http.StatusBadRequest, "DBInstanceAlreadyExists", requestID, "DB instance "+newID+" already exists.", rdsXMLNamespace)
		return
	}
	if err := h.cnpg.createRestoredInstance(ctx, newID, snapID, src); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "RestoreDBInstanceFromDBSnapshot", newID, "allow", "from "+snapID)
	v, _ := h.cnpg.getInstance(ctx, newID)
	h.writeInstanceResponse(ctx, w, requestID, "RestoreDBInstanceFromDBSnapshot", v)
}

// --- snapshots ---

func (h *rdsHandler) createDBSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	snapID := r.PostFormValue("DBSnapshotIdentifier")
	instID := r.PostFormValue("DBInstanceIdentifier")
	if !dbIdentifierRE.MatchString(snapID) {
		h.paramErr(w, requestID, "DBSnapshotIdentifier must be 1-63 chars, lowercase alnum or hyphens, starting with a letter.")
		return
	}
	v, err := h.cnpg.getInstance(ctx, instID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !v.found {
		writeQueryError(w, http.StatusNotFound, "DBInstanceNotFound", requestID, "DB instance "+instID+" not found.", rdsXMLNamespace)
		return
	}
	if v.status != "available" {
		writeQueryError(w, http.StatusBadRequest, "InvalidDBInstanceState", requestID, "DB instance "+instID+" is not available (status "+v.status+").", rdsXMLNamespace)
		return
	}
	if ex, err := h.cnpg.getSnapshot(ctx, snapID); err == nil && ex.found {
		writeQueryError(w, http.StatusBadRequest, "DBSnapshotAlreadyExists", requestID, "Cannot create the snapshot because a snapshot with the identifier "+snapID+" already exists.", rdsXMLNamespace)
		return
	}
	if err := h.cnpg.createSnapshot(ctx, snapID, v); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateDBSnapshot", snapID, "allow", "of "+instID)
	h.writeXML(w, requestID, "CreateDBSnapshot", "<CreateDBSnapshotResult>"+dbSnapshotXML(snapshotView{id: snapID, instance: instID, status: "creating", found: true, source: v}, h.snapshotArn(ctx, snapID))+"</CreateDBSnapshotResult>")
}

func (h *rdsHandler) describeDBSnapshots(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBSnapshotIdentifier")
	var snaps []snapshotView
	if id != "" {
		s, err := h.cnpg.getSnapshot(ctx, id)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !s.found {
			writeQueryError(w, http.StatusNotFound, "DBSnapshotNotFound", requestID, "DB snapshot "+id+" not found.", rdsXMLNamespace)
			return
		}
		snaps = []snapshotView{s}
	} else {
		var err error
		if snaps, err = h.cnpg.listSnapshots(ctx); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	var sb strings.Builder
	sb.WriteString("<DescribeDBSnapshotsResult><DBSnapshots>")
	for _, s := range snaps {
		sb.WriteString(dbSnapshotXML(s, h.snapshotArn(ctx, s.id)))
	}
	sb.WriteString("</DBSnapshots></DescribeDBSnapshotsResult>")
	h.writeXML(w, requestID, "DescribeDBSnapshots", sb.String())
}

func (h *rdsHandler) deleteDBSnapshot(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	id := r.PostFormValue("DBSnapshotIdentifier")
	s, err := h.cnpg.getSnapshot(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !s.found {
		writeQueryError(w, http.StatusNotFound, "DBSnapshotNotFound", requestID, "DB snapshot "+id+" not found.", rdsXMLNamespace)
		return
	}
	if err := h.cnpg.deleteSnapshot(ctx, id); err != nil {
		h.internal(w, requestID, err)
		return
	}
	s.status = "deleted"
	h.audit(ctx, "DeleteDBSnapshot", id, "allow", "")
	h.writeXML(w, requestID, "DeleteDBSnapshot", "<DeleteDBSnapshotResult>"+dbSnapshotXML(s, h.snapshotArn(ctx, id))+"</DeleteDBSnapshotResult>")
}

// --- XML rendering ---

func (h *rdsHandler) writeInstanceResponse(ctx context.Context, w http.ResponseWriter, requestID, action string, v instanceView) {
	h.writeXML(w, requestID, action, "<"+action+"Result>"+dbInstanceXML(v, h.instanceArn(ctx, v.id))+"</"+action+"Result>")
}

func (h *rdsHandler) writeXML(w http.ResponseWriter, requestID, action, inner string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xmlHeader))
	_, _ = w.Write([]byte("<" + action + "Response xmlns=\"" + rdsXMLNamespace + "\">"))
	_, _ = w.Write([]byte(inner))
	_, _ = w.Write([]byte("<ResponseMetadata><RequestId>" + requestID + "</RequestId></ResponseMetadata>"))
	_, _ = w.Write([]byte("</" + action + "Response>"))
}

func dbInstanceXML(v instanceView, arn string) string {
	var sb strings.Builder
	sb.WriteString("<DBInstance>")
	el(&sb, "DBInstanceIdentifier", v.id)
	el(&sb, "DBInstanceArn", arn)
	el(&sb, "DBInstanceStatus", v.status)
	el(&sb, "Engine", v.engine)
	el(&sb, "EngineVersion", strOrDefault(v.engineVersion, rdsDefaultEngineVersion))
	el(&sb, "DBInstanceClass", v.instanceClass)
	el(&sb, "MasterUsername", v.masterUser)
	el(&sb, "DBName", v.dbName)
	el(&sb, "AllocatedStorage", itoa(v.allocatedGB))
	el(&sb, "StorageEncrypted", boolStr(v.storageEncrypted))
	el(&sb, "DeletionProtection", boolStr(v.deletionProtected))
	el(&sb, "MultiAZ", "false")
	el(&sb, "BackupRetentionPeriod", "0")
	// Endpoint is populated only once the instance genuinely accepts connections.
	if v.status == "available" {
		sb.WriteString("<Endpoint>")
		el(&sb, "Address", v.endpoint)
		el(&sb, "Port", itoa(v.port))
		sb.WriteString("</Endpoint>")
	}
	sb.WriteString("</DBInstance>")
	return sb.String()
}

func dbSnapshotXML(s snapshotView, arn string) string {
	var sb strings.Builder
	sb.WriteString("<DBSnapshot>")
	el(&sb, "DBSnapshotIdentifier", s.id)
	el(&sb, "DBSnapshotArn", arn)
	el(&sb, "DBInstanceIdentifier", s.instance)
	el(&sb, "Status", s.status)
	el(&sb, "Engine", strOrDefault(s.source.engine, "postgres"))
	if s.source.allocatedGB > 0 {
		el(&sb, "AllocatedStorage", strconv.Itoa(s.source.allocatedGB))
	}
	if s.source.masterUser != "" {
		el(&sb, "MasterUsername", s.source.masterUser)
	}
	el(&sb, "Port", "5432")
	el(&sb, "Encrypted", boolStr(s.source.storageEncrypted))
	el(&sb, "SnapshotType", "manual")
	sb.WriteString("</DBSnapshot>")
	return sb.String()
}

func el(sb *strings.Builder, name, val string) {
	sb.WriteString("<" + name + ">" + xmlEscape(val) + "</" + name + ">")
}

// --- helpers ---

func (h *rdsHandler) paramErr(w http.ResponseWriter, requestID, msg string) {
	writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg, rdsXMLNamespace)
}

func (h *rdsHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("rds backend error", "error", err.Error())
	writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "An internal error occurred.", rdsXMLNamespace)
}

func (h *rdsHandler) audit(ctx context.Context, op, res, decision, detail string) {
	args := []any{"service", "rds", "op", op, "decision", decision, "principal", principalFromCtx(ctx)}
	if res != "" {
		args = append(args, "resource", res)
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	h.logger.InfoContext(ctx, "rds audit", args...)
}

func formFirst(r *http.Request, keys ...string) string {
	for _, k := range keys {
		if v := r.PostFormValue(k); v != "" {
			return v
		}
	}
	return ""
}

func boolForm(r *http.Request, key string) bool {
	return strings.EqualFold(r.PostFormValue(key), "true")
}

// tagsFromForm parses RDS's Tags.member.N.Key / .Value query-protocol tag encoding.
func tagsFromForm(r *http.Request) map[string]string {
	out := map[string]string{}
	for i := 1; i <= 50; i++ {
		k := r.PostFormValue("Tags.member." + itoa(i) + ".Key")
		if k == "" {
			break
		}
		out[k] = r.PostFormValue("Tags.member." + itoa(i) + ".Value")
	}
	return out
}
