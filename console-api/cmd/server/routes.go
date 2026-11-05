package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/crd"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	"github.com/harn3ss/open-infra/console-api/internal/watch"
)

// The console's route table: every /api route with the IAM action it is and the resource ARN it acts
// on — the question the equivalent AWS API call asks. A route with no entry can't exist (the coverage
// test fails), and a public one says why it needs no authorization.

const apiPrefix = "/api"

func registerAPIRoutes(api chi.Router, z *consoleAuthz, client *k8s.Client, auth *authStore, buckets *bucketAuthz, logger *slog.Logger) {
	cs := *client.Clientset
	h := func(method, path string, timeout time.Duration, action string, arn arnFunc, hf http.HandlerFunc) {
		z.handle(api, apiPrefix, method, path, timeout, action, arn, hf)
	}
	get, post, put, patch, del := http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete
	const s10, s12, s15, s20, s25, s30 = 10 * time.Second, 12 * time.Second, 15 * time.Second, 20 * time.Second, 25 * time.Second, 30 * time.Second

	// Sign-in and the console's own metadata.
	api.Post("/auth/login", handleLogin(auth))
	api.Post("/auth/logout", handleLogout(auth))
	api.Get("/auth/me", handleMe(auth))
	z.public(post, "/api/auth/login", "sign-in")
	z.public(post, "/api/auth/logout", "sign-out")
	z.public(get, "/api/auth/me", "who am I: the UI renders for any signed-in principal, policy or not")
	// A signed-in user's own password, proven by the old one: the forced change a PasswordResetRequired
	// sign-in must make before anything else, so it cannot wait on IAM policy (AWS lets a user change its
	// own password at that prompt). It checks its own session and CSRF header.
	api.Post("/auth/change-password", handleChangeOwnPassword(auth))
	z.public(post, "/api/auth/change-password", "a signed-in user changes its own password, proving the old one (the forced change at sign-in)")
	// Runtime config: read from env on every request so a redeploy or ConfigMap change is picked up
	// without rebuilding the SPA.
	api.Get("/config", handleConfig)
	z.public(get, "/api/config", "runtime UI configuration (cluster name, version, auth mode); no resource data")
	// CRD schema (short-lived).
	z.public(get, "/api/crd-schema", "the published form schema of a platform resource type; no resource data")
	api.With(middleware.Timeout(s15)).Get("/crd-schema", handleCRDSchema(crd.New(client.Host, client.Transport), logger))
	// Architecture capability (#41 Phase 3): which kinds this cluster's node architectures can run.
	z.public(get, "/api/capabilities", "which resource types the cluster's architectures can run; no resource data")
	api.With(middleware.Timeout(s15)).Get("/capabilities", handleCapabilities(cs, logger))
	z.public(get, "/api/iam/config", "static IAM page metadata (identity namespace, policy vocabulary)")
	api.With(middleware.Timeout(s15)).Get("/iam/config", handleIAMConfig(auth))

	// CloudWatch: the dashboard picker (server-side proxy to Grafana's /api/search).
	h(get, "/grafana/dashboards", s15, "cloudwatch:ListDashboards", nil, handleGrafanaDashboards(logger))

	// S3: the bucket browser. Each handler also runs the shim's object-storage check (bucket_authz.go):
	// the platform-bucket fence and the object-level decision.
	h(get, "/buckets", s15, "s3:ListAllMyBuckets", nil, handleBuckets(cs, buckets, logger))
	h(get, "/buckets/{bucket}/objects", s20, "s3:ListBucket", bucketARN, handleBucketObjects(cs, buckets, logger))
	h(post, "/buckets", s10, "s3:CreateBucket", bodyARN("name", func(_ *http.Request, v string) string { return "arn:aws:s3:::" + v }), handleCreateBucket(cs, buckets, logger))
	h(del, "/buckets/{bucket}", s10, "s3:DeleteBucket", bucketARN, handleDeleteBucket(cs, buckets, logger))
	h(put, "/buckets/{bucket}/object", 0, "s3:PutObject", objectARN, handleUploadObject(cs, buckets, logger))
	h(get, "/buckets/{bucket}/object", 0, "s3:GetObject", objectARN, handleDownloadObject(cs, buckets, logger))
	h(del, "/buckets/{bucket}/object", s10, "s3:DeleteObject", objectARN, handleDeleteObject(cs, buckets, logger))

	// SQS (JetStream streams).
	h(get, "/queues", s10, "sqs:ListQueues", nil, handleQueues(logger))
	h(post, "/queues/publish", s10, "sqs:SendMessage", bodyARN("subject", func(r *http.Request, v string) string {
		name, _, _ := strings.Cut(v, ".")
		return "arn:aws:sqs:" + awsaction.DefaultRegion + ":" + callerAccount(r) + ":" + name
	}), handleQueuePublish(logger))
	h(get, "/queues/{stream}/messages", s10, "sqs:ReceiveMessage", queueARN, handleQueuePeek(logger))
	h(post, "/queues/{stream}/purge", s15, "sqs:PurgeQueue", queueARN, handleQueuePurge(logger))

	// SageMaker, Lambda, AppSync interactions.
	h(post, "/models/{namespace}/{name}/chat", 125*time.Second, "sagemaker:InvokeEndpoint", z.kindARN("Model"), handleModelChat(cs, logger))
	h(get, "/functions/{namespace}/{name}/routes", s30, "lambda:GetFunction", z.kindARN("Function"), handleFunctionRoutes(cs, logger))
	h(get, "/functions/{namespace}/{name}/code", s30, "lambda:GetFunction", z.kindARN("Function"), handleFunctionCode(cs, logger))
	h(post, "/functions/{namespace}/{name}/invoke", 65*time.Second, "lambda:InvokeFunction", z.kindARN("Function"), handleFunctionInvoke(cs, logger))
	// AppSync's EvaluateMappingTemplate takes no resource-level permission.
	h(post, "/graphqlapis/{namespace}/{name}/test-resolver", 35*time.Second, "appsync:EvaluateMappingTemplate", nil, handleGraphQLTestResolver(cs, logger))

	// DMS, data flows, database insight, Directory Service, Athena, Glue.
	h(post, "/migrations/discover", s15, "dms:RefreshSchemas", nil, handleMigrationDiscover(logger))
	h(get, "/migrations/{namespace}/{name}/status", s15, "dms:DescribeReplicationTasks", z.kindARN("Migration"), handleMigrationStatus(logger))
	h(get, "/replications/{namespace}/{name}/status", s15, "dms:DescribeReplicationTasks", z.kindARN("Replication"), handleReplicationStatus(logger))
	h(post, "/dataflows/{namespace}/{name}/status", s15, "openinfra:GetDataFlow", z.kindARN("DataFlow"), handleDataFlowStatus(logger))
	h(post, "/db-stats", s15, "pi:DescribeDimensionKeys", nil, handleDBStats(cs, client.Host, client.Transport, logger))
	h(post, "/databases/{namespace}/{name}/stats", s15, "pi:GetResourceMetrics", nil, handleManagedDBStats(cs, logger))
	h(post, "/directories/{namespace}/{name}/ldap", s15, "ds:DescribeDirectories", z.kindARN("Directory"), handleDirectoryLDAP(cs, logger))
	h(get, "/queries/{namespace}/{name}/result", s15, "athena:GetQueryResults", z.kindARN("Query"), handleQueryResult(cs, buckets, logger))
	h(get, "/catalog/tables", s15, "glue:GetTables", nil, handleCatalogTables(logger))

	// Cost Explorer, and the operator's node view.
	h(get, "/cost", s15, "ce:GetCostAndUsage", nil, handleCost(cs, logger))
	h(get, "/nodes/disk", s12, "openinfra-operator:ListNodes", nil, handleNodeDisk(cs, auth, logger))

	// RDS snapshots and backtrack.
	h(post, "/databases/{namespace}/{name}/snapshot", s20, "rds:CreateDBSnapshot", z.rdsARN("db"), handleSnapshotCreate(cs, auth, logger))
	h(get, "/snapshots", s20, "rds:DescribeDBSnapshots", nil, handleSnapshotList(cs, logger))
	h(post, "/snapshots/restore", s20, "rds:RestoreDBInstanceFromDBSnapshot", z.snapshotARN("rds", true), handleSnapshotRestore(cs, auth, logger))
	h(post, "/databases/{namespace}/{name}/backtrack", s20, "rds:BacktrackDBCluster", z.rdsARN("cluster"), handleBacktrack(cs, auth, logger))
	h(del, "/snapshots", s20, "rds:DeleteDBSnapshot", z.snapshotARN("rds", false), handleSnapshotDelete(cs, auth, logger))

	// EC2 snapshots of a VM's root disk.
	h(post, "/vms/{namespace}/{name}/snapshot", s20, "ec2:CreateSnapshots", z.kindARN("VirtualMachine"), handleVMSnapshotCreate(cs, auth, logger))
	h(get, "/vm-snapshots", s20, "ec2:DescribeSnapshots", nil, handleVMSnapshotList(cs, logger))
	h(post, "/vm-snapshots/restore", s20, "ec2:RunInstances", nil, handleVMSnapshotRestore(cs, auth, logger))
	h(del, "/vm-snapshots", s20, "ec2:DeleteSnapshot", z.snapshotARN("ec2", false), handleVMSnapshotDelete(cs, auth, logger))

	// SageMaker jobs: register, logs (CloudWatch Logs), metrics, model-monitor reports.
	h(post, "/trainingjobs/{namespace}/{name}/register", s20, "sagemaker:CreateModelPackage", nil, handleTrainingJobRegister(cs, auth, logger))
	h(get, "/jobs/{namespace}/{name}/logs", 0, "logs:GetLogEvents", nil, handleJobLogs(cs, logger))
	h(get, "/jobs/{namespace}/{name}/metrics", s15, "cloudwatch:GetMetricData", nil, handleJobMetrics(cs, logger))
	h(get, "/modelmonitors/{namespace}/{name}/report", s20, "sagemaker:DescribeMonitoringSchedule", z.kindARN("ModelMonitor"), handleModelMonitorReport(cs, logger))

	// IAM: users.
	h(get, "/iam/users", s15, "iam:ListUsers", nil, handleIAMUsersList(cs, auth, logger))
	h(post, "/iam/users", s15, "iam:CreateUser", bodyARN("name", iamBodyARN("user")), handleIAMUserCreate(cs, auth, logger))
	h(get, "/iam/users/{name}", s15, "iam:GetUser", iamARN("user"), handleIAMUserGet(cs, auth, logger))
	h(patch, "/iam/users/{name}", s15, "iam:UpdateUser", iamARN("user"), handleIAMUserUpdate(cs, auth, logger))
	// A password: your own is iam:ChangePassword (AWS's self-service action); another user's is
	// iam:UpdateLoginProfile.
	z.handleDynamic(api, apiPrefix, post, "/iam/users/{name}/password", s15, "iam:ChangePassword | iam:UpdateLoginProfile",
		func(r *http.Request) (string, string) {
			name := chi.URLParam(r, "name")
			arn := iamEntityARN("user", callerAccount(r), name)
			if c, ok := claimsFrom(r); ok && c.Sub == name {
				return "iam:ChangePassword", arn
			}
			return "iam:UpdateLoginProfile", arn
		}, handleIAMUserPassword(cs, auth, logger))
	h(del, "/iam/users/{name}", s15, "iam:DeleteUser", iamARN("user"), handleIAMUserDelete(cs, auth, logger))
	h(put, "/iam/users/{name}/tags", s15, "iam:TagUser", iamARN("user"), handleIAMTagsUpdate(cs, auth, logger, "users", "user", usersAbsPath))
	// Access keys (the AWS "Security credentials" surface). Keys live in the shim's KEYS_NAMESPACE.
	keysNS := getenv("KEYS_NAMESPACE", "open-infra-aws-shim")
	h(get, "/iam/users/{name}/access-keys", s15, "iam:ListAccessKeys", iamARN("user"), handleIAMAccessKeysList(cs, auth, keysNS, logger))
	h(post, "/iam/users/{name}/access-keys", s15, "iam:CreateAccessKey", iamARN("user"), handleIAMAccessKeyCreate(cs, auth, keysNS, logger))
	h(patch, "/iam/users/{name}/access-keys/{id}", s15, "iam:UpdateAccessKey", iamARN("user"), handleIAMAccessKeyUpdate(cs, auth, keysNS, logger))
	h(del, "/iam/users/{name}/access-keys/{id}", s15, "iam:DeleteAccessKey", iamARN("user"), handleIAMAccessKeyDelete(cs, auth, keysNS, logger))

	// IAM: groups (policy containers).
	h(get, "/iam/groups", s15, "iam:ListGroups", nil, handleIAMGroupsList(cs, auth, logger))
	h(post, "/iam/groups", s15, "iam:CreateGroup", bodyARN("name", iamBodyARN("group")), handleIAMGroupCreate(cs, auth, logger))
	h(get, "/iam/groups/{name}", s15, "iam:GetGroup", iamARN("group"), handleIAMGroupGet(cs, auth, logger))
	h(patch, "/iam/groups/{name}", s15, "iam:UpdateGroup", iamARN("group"), handleIAMGroupUpdate(cs, auth, logger))
	h(del, "/iam/groups/{name}", s15, "iam:DeleteGroup", iamARN("group"), handleIAMGroupDelete(cs, auth, logger))

	// IAM: policies and roles.
	h(get, "/iam/policies", s15, "iam:ListPolicies", nil, handleIAMPoliciesList(cs, auth, logger))
	h(post, "/iam/policies", s15, "iam:CreatePolicy", bodyARN("name", iamBodyARN("policy")), handleIAMPolicyCreate(cs, auth, logger))
	h(get, "/iam/policies/{name}", s15, "iam:GetPolicy", iamARN("policy"), handleIAMPolicyGet(cs, auth, logger))
	h(patch, "/iam/policies/{name}", s15, "iam:CreatePolicyVersion", iamARN("policy"), handleIAMPolicyUpdate(cs, auth, logger))
	h(del, "/iam/policies/{name}", s15, "iam:DeletePolicy", iamARN("policy"), handleIAMPolicyDelete(cs, auth, logger))
	h(put, "/iam/policies/{name}/tags", s15, "iam:TagPolicy", iamARN("policy"), handleIAMTagsUpdate(cs, auth, logger, "policies", "policy", policiesAbsPath))
	h(get, "/iam/policies/{name}/revision", s15, "iam:GetPolicyVersion", iamARN("policy"), handleIAMPolicyRevision(cs, auth, logger))
	h(get, "/iam/roles", s15, "iam:ListRoles", nil, handleIAMRolesList(cs, auth, logger))
	h(post, "/iam/roles", s15, "iam:CreateRole", bodyARN("name", iamBodyARN("role")), handleIAMRoleCreate(cs, auth, logger))
	h(get, "/iam/roles/{name}", s15, "iam:GetRole", iamARN("role"), handleIAMRoleGet(cs, auth, logger))
	h(patch, "/iam/roles/{name}", s15, "iam:UpdateRole", iamARN("role"), handleIAMRoleUpdate(cs, auth, logger))
	h(del, "/iam/roles/{name}", s15, "iam:DeleteRole", iamARN("role"), handleIAMRoleDelete(cs, auth, logger))
	// AWS's "Revoke active sessions" attaches an inline deny-older-sessions policy to the role.
	h(post, "/iam/roles/{name}/revoke-sessions", s15, "iam:PutRolePolicy", iamARN("role"), handleIAMRoleRevokeSessions(cs, auth, logger))
	h(put, "/iam/roles/{name}/tags", s15, "iam:TagRole", iamARN("role"), handleIAMTagsUpdate(cs, auth, logger, "roles", "role", rolesAbsPath))
	h(post, "/iam/simulate", s15, "iam:SimulatePrincipalPolicy", nil, handleIAMSimulate(cs, auth, logger))
	// The AWS-policy import preview writes nothing: IAM Access Analyzer's policy validation.
	h(post, "/iam/import", s15, "access-analyzer:ValidatePolicy", nil, handleIAMImport(cs, auth, logger))

	// Temporal grants: attaching (and detaching) a policy to the subject, as IAM.
	h(get, "/iam/grants", s15, "iam:ListAttachedUserPolicies", nil, handleIAMGrantsList(cs, auth, logger))
	z.handleDynamic(api, apiPrefix, post, "/iam/grants", s15, "iam:Attach{User,Group,Role}Policy", grantQuestion, handleIAMGrantCreate(cs, auth, logger))
	h(get, "/iam/grants/{name}", s15, "iam:ListAttachedUserPolicies", nil, handleIAMGrantGet(cs, auth, logger))
	h(post, "/iam/grants/{name}/approve", s15, "iam:AttachUserPolicy", nil, handleIAMGrantApprove(cs, auth, logger))
	h(del, "/iam/grants/{name}", s15, "iam:DetachUserPolicy", nil, handleIAMGrantDelete(cs, auth, logger))
	h(get, "/iam/access-review", s25, "iam:GetCredentialReport", nil, handleAccessReview(cs, auth, logger))
	h(get, "/iam/access-advisor", s25, "iam:GetServiceLastAccessedDetails", nil, handleIAMAccessAdvisor(cs, auth, logger))

	// CloudTrail, compliance, KMS, Private CA, lineage.
	h(get, "/audit", s20, "cloudtrail:LookupEvents", nil, handleAudit(cs, auth, logger))
	h(get, "/audit/integrity", s15, "cloudtrail:GetTrailStatus", nil, handleAuditIntegrity(cs, auth, logger))
	h(get, "/compliance/classification", s20, "macie2:GetFindingStatistics", nil, handleClassificationCompliance(cs, auth, logger))
	h(get, "/encryption/keys", s15, "kms:ListKeys", nil, handleEncryptionKeys(cs, auth, logger))
	h(get, "/encryption/destructions", s15, "kms:ListKeys", nil, handleDestructions(cs, auth, logger))
	h(get, "/ca", s15, "acm-pca:ListCertificateAuthorities", nil, handleCertificateAuthorities(cs, auth, logger))
	h(post, "/ca/{namespace}/{name}/issue", s15, "acm-pca:IssueCertificate", z.kindARN("CertificateAuthority"), handleCAIssue(cs, auth, logger))
	h(post, "/ca/{namespace}/{name}/revoke", s15, "acm-pca:RevokeCertificate", z.kindARN("CertificateAuthority"), handleCARevoke(cs, auth, logger))
	h(get, "/lineage", s20, "datazone:GetLineageNode", nil, handleLineage(cs, auth, logger))
	h(get, "/compliance/attestation", s20, "auditmanager:GetAssessment", nil, handleAttestation(cs, auth, logger))

	// Switch role (the AWS console's): sts:AssumeRole on the role, whose trust must name the caller.
	z.handleDynamic(api, apiPrefix, post, "/sts/switch-role", s15, "sts:AssumeRole on the role", switchRoleQuestion, handleSwitchRole(cs, auth, logger))
	z.public(post, "/api/sts/switch-back", "returns the session to the signed-in user (drops the assumed role)")
	api.With(middleware.Timeout(s15)).Post("/sts/switch-back", handleSwitchBack(auth, logger))

	// Watch (long-lived SSE): NO request timeout — the stream must stay open. Authorized per request by
	// the resource it watches.
	z.perRequest([]string{get}, "/api/watch", "the watched resource's list action (awsaction.ForKubernetes)")
	api.Get("/watch", z.watchHandler(watch.New(client.Host, client.Transport, logger)).ServeHTTP)

	// Kubernetes reverse proxy (CRUD). Mounted under /api/k8s and stripped before forwarding. No write
	// timeout so large applies / log follows are not cut off. Each request is authorized by its AWS action
	// (awsaction.ForKubernetes) and forwarded as the principal (impersonation; generated RBAC re-checks).
	rp := proxy.New(client.Host, client.Transport, k8sPrefix, logger, z.proxyIdentity)
	gated := z.proxyHandler(k8sPrefix, rp)
	z.perRequest(allMethods, "/api/k8s", "the Kubernetes request's AWS action (awsaction.ForKubernetes)")
	z.perRequest(allMethods, "/api/k8s/*", "the Kubernetes request's AWS action (awsaction.ForKubernetes)")
	api.Handle("/k8s", gated)
	api.Handle("/k8s/*", gated)
}

// handleDynamic registers a route whose action depends on the request: question returns the action and
// ARN to ask; the registry records describe.
func (z *consoleAuthz) handleDynamic(rt chi.Router, prefix, method, path string, timeout time.Duration, describe string,
	question func(*http.Request) (string, string), hf http.HandlerFunc) {
	z.reg.Add(awsaction.Route{Method: method, Path: prefix + path, Action: "per-request: " + describe})
	mws := []func(http.Handler) http.Handler{}
	if timeout > 0 {
		mws = append(mws, middleware.Timeout(timeout))
	}
	mws = append(mws, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			action, arn := question(r)
			if ok, reason := z.decide(r, action, arn, allowLegacy); !ok {
				writeAccessDenied(w, action, arn, reason)
				return
			}
			if z.enforced(r) {
				r = r.WithContext(withRouteAuthorized(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	})
	rt.With(mws...).MethodFunc(method, path, hf)
}

// grantQuestion is a grant request's IAM question: attaching a policy to its subject (a user, group or
// role), on the subject's ARN.
func grantQuestion(r *http.Request) (string, string) {
	kind := strings.ToLower(peekBody(r, "subjectKind"))
	name := peekBody(r, "subjectName")
	switch kind {
	case "group":
		return "iam:AttachGroupPolicy", iamEntityARN("group", callerAccount(r), name)
	case "role":
		return "iam:AttachRolePolicy", iamEntityARN("role", callerAccount(r), name)
	}
	return "iam:AttachUserPolicy", iamEntityARN("user", callerAccount(r), name)
}

// bodyARN builds an ARN from one string field of the request's JSON body (a create names its resource
// there), restoring the body for the handler.
func bodyARN(field string, build func(r *http.Request, v string) string) arnFunc {
	return func(r *http.Request) string {
		v := peekBody(r, field)
		if v == "" {
			return "*"
		}
		return build(r, v)
	}
}

// iamBodyARN builds the IAM ARN of the entity a create names.
func iamBodyARN(kind string) func(r *http.Request, v string) string {
	return func(r *http.Request, v string) string { return iamEntityARN(kind, callerAccount(r), v) }
}

// maxPeek bounds how much of a request body the gate reads to find the resource a create names.
const maxPeek = 1 << 20

// peekBody reads a string field of the request's JSON body and puts the body back for the handler. A
// body that isn't a JSON object, or is larger than maxPeek, yields "".
func peekBody(r *http.Request, field string) string {
	b, ok := peekRaw(r)
	if !ok {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[field].(string)
	return strings.TrimSpace(s)
}

// peekRaw reads up to maxPeek bytes of the request body and puts the whole body back for the handler:
// what was read, then the unread rest. ok is false when there is no body or it is larger than maxPeek.
func peekRaw(r *http.Request) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxPeek+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(b), r.Body), r.Body}
	if err != nil || len(b) > maxPeek {
		return nil, false
	}
	return b, true
}

// snapshotARN is the ARN of the snapshot a route names in its query string (?namespace=&id=, a delete) or
// its JSON body ({"namespace","id"}, a restore), in the namespace's account: an RDS DB snapshot
// (arn:aws:rds:<region>:<account>:snapshot:<id>) or an EC2 one (arn:aws:ec2:<region>:<account>:snapshot/<id>),
// as AWS authorizes rds:DeleteDBSnapshot, ec2:DeleteSnapshot and a restore on the snapshot; "*" when the
// request names none (the handler then refuses it).
func (z *consoleAuthz) snapshotARN(service string, fromBody bool) arnFunc {
	return func(r *http.Request) string {
		ns, id := r.URL.Query().Get("namespace"), r.URL.Query().Get("id")
		if fromBody {
			ns, id = peekBody(r, "namespace"), peekBody(r, "id")
		}
		if id == "" {
			return "*"
		}
		acct := z.namespaceAccount(r.Context(), ns)
		if service == "ec2" {
			return "arn:aws:ec2:" + awsaction.DefaultRegion + ":" + acct + ":snapshot/" + id
		}
		return "arn:aws:rds:" + awsaction.DefaultRegion + ":" + acct + ":snapshot:" + id
	}
}

// rdsARN is the RDS ARN (db or cluster) of the {namespace}/{name} database, in its namespace's account.
func (z *consoleAuthz) rdsARN(kind string) arnFunc {
	return func(r *http.Request) string {
		acct := z.namespaceAccount(r.Context(), chi.URLParam(r, "namespace"))
		return "arn:aws:rds:" + awsaction.DefaultRegion + ":" + acct + ":" + kind + ":" + chi.URLParam(r, "name")
	}
}
