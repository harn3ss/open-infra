// SSM Run Command's agent channel (#347 item 22): /v1/vm-commands on the shim's in-cluster TLS port, where
// a VM's metadata agent (vm-composition.yaml, CommandRunner) fetches the commands SendCommand sent its
// instance and reports how each ran.
//
// The agent is identified as /v1/vm-credentials identifies it: by its per-VM ServiceAccount token, verified
// with a TokenReview and bound to the VM's own launcher pod (k8sSARoleResolver), never by anything in the
// request. The instance id is the shim's own (the VM's status.instanceId, ec2_ids.go), so an agent fetches
// and reports only its own instance's invocations. As on AWS, an instance is managed when it has an
// instance role (its ServiceAccount names one: every VM with instance metadata has a token, for its signed
// identity document, but a token without a role is refused here) that trusts the vm principal and allows the SSM agent's
// actions — ssm:UpdateInstanceInformation and ec2messages:GetMessages to register and fetch,
// ec2messages:SendReply to report (AmazonSSMManagedInstanceCore attaches them) — and when it is in an
// account's namespace that SendCommand reaches: the management account's stack namespace, or a member
// account's home. A member account's instance is that account's: its agent acts in it (its role is decided
// in its own account), and only that account's commands reach it. GET long-polls: it answers as soon as a
// command is pending, or empty after the agent's wait (at most 20 s).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

const vmCommandsPath = "/v1/vm-commands"

// isVMCommandsPath reports whether a path is the agent channel (/v1/vm-commands or /v1/vm-commands/<id>).
func isVMCommandsPath(p string) bool {
	p = path.Clean("/" + p)
	return p == vmCommandsPath || strings.HasPrefix(p, vmCommandsPath+"/")
}

// commandBus wakes an instance's waiting poll on this replica when a command is sent to it; a poll on
// another replica finds it at its next store check.
type commandBus struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]bool
}

func (b *commandBus) subscribe(id string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	if b.waiters == nil {
		b.waiters = map[string]map[chan struct{}]bool{}
	}
	if b.waiters[id] == nil {
		b.waiters[id] = map[chan struct{}]bool{}
	}
	b.waiters[id][ch] = true
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.waiters[id], ch)
		if len(b.waiters[id]) == 0 {
			delete(b.waiters, id)
		}
		b.mu.Unlock()
	}
}

func (b *commandBus) notify(ids ...string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range ids {
		for ch := range b.waiters[id] {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// vmAgent is a verified agent: its instance, the instance role's session identity, and the member account
// it acts in ("" for the management account's instance) with that account's home.
type vmAgent struct {
	instanceID, namespace, vmName, role string
	account, accountHome                string
	claims                              iam.Claims
	expires                             time.Time
}

// actingIn is ctx acting in the agent's account: a member account's instance's role is decided as a
// request within its own account (withAccount, inAccountScope); the management account's ctx is unchanged.
func (a vmAgent) actingIn(ctx context.Context) context.Context {
	if a.account == "" {
		return ctx
	}
	return inAccountScope(withAccount(ctx, a.account, a.accountHome))
}

type vmCommandsHandler struct {
	resolver   saRoleResolver
	trust      roleTrustChecker
	store      *ssmStore
	dyn        dynamic.Interface // the shim's client: a VM's claim (and composite), for its instance id
	authz      *dataplaneauthz.Checker
	home       string          // the IAM home namespace (ROLES_NAMESPACE), as the session principal names it
	namespaces map[string]bool // the management account's namespaces: only their VMs (and members' below) are managed
	// accounts knows the member accounts' homes: a VM in a member account's home is that account's managed
	// instance (nil: the management account's namespaces alone).
	accounts vmAccounts
	bus      *commandBus
	maxWait  time.Duration // the longest long-poll
	recheck  time.Duration // how often a waiting poll re-reads the store
	cacheTTL time.Duration // how long a verified token is trusted without a new TokenReview
	logger   *slog.Logger

	mu        sync.Mutex
	cache     map[string]vmAgent
	lastSweep time.Time
}

func (h *vmCommandsHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	if refuseIfProxied(w, r) { // in-cluster only, as /v1/vm-credentials
		return
	}
	token := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	if token == "" {
		http.Error(w, "missing instance identity token", http.StatusUnauthorized)
		return
	}
	if h.store == nil {
		http.Error(w, "Run Command is not configured on this shim (no SSM store)", http.StatusServiceUnavailable)
		return
	}
	a, status, msg := h.identify(r.Context(), token)
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	switch {
	case p == vmCommandsPath && r.Method == http.MethodGet:
		h.poll(w, r, a)
	case strings.HasPrefix(p, vmCommandsPath+"/") && r.Method == http.MethodPost:
		h.report(w, r, a, strings.TrimPrefix(p, vmCommandsPath+"/"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// identify verifies the token and resolves the managed instance it belongs to (cached for cacheTTL).
func (h *vmCommandsHandler) identify(ctx context.Context, token string) (vmAgent, int, string) {
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	now := time.Now()
	h.mu.Lock()
	if a, ok := h.cache[key]; ok && now.Before(a.expires) {
		h.mu.Unlock()
		return a, 0, ""
	}
	h.mu.Unlock()
	id, ok := h.resolver.resolveSARole(ctx, token)
	if !ok {
		return vmAgent{}, http.StatusUnauthorized, "unauthorized"
	}
	if id.role == "" {
		return vmAgent{}, http.StatusForbidden, "this VM has no instance role (spec.instanceRole), so it is not a managed instance"
	}
	// The management account's namespaces, else a member account's home (its instances are there).
	var acct, acctHome string
	if !h.namespaces[id.namespace] {
		acct, acctHome = vmMemberAccount(h.accounts, id.namespace)
		if acct == "" || acctHome != id.namespace {
			return vmAgent{}, http.StatusNotFound, "VMs in namespace " + id.namespace + " are not managed instances of this account"
		}
		if h.accounts.Suspended(acct) {
			return vmAgent{}, http.StatusForbidden, "the instance's account is suspended"
		}
	}
	groups, ok := h.trust.vmTrusted(ctx, id.namespace, id.role)
	if !ok {
		return vmAgent{}, http.StatusForbidden, "the instance role does not trust the vm principal (its spec.trust must include \"vm\")"
	}
	if h.dyn == nil {
		return vmAgent{}, http.StatusServiceUnavailable, "the shim cannot read the VM"
	}
	claim, err := h.dyn.Resource(vmClaimGVR).Namespace(id.namespace).Get(ctx, id.vmName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return vmAgent{}, http.StatusNotFound, "the VM is gone"
	}
	if err != nil {
		return vmAgent{}, http.StatusServiceUnavailable, "the VM could not be read; retry"
	}
	inst := vmInstanceID(ctx, claim, h.dyn)
	if inst == "" {
		return vmAgent{}, http.StatusServiceUnavailable, "the VM has no instance id yet; retry"
	}
	home := h.home
	if home == "" {
		home = dataplaneauthz.DefaultHomeNamespace
	}
	// The role's session, as /v1/vm-credentials mints it: a member account's in that account.
	a := vmAgent{instanceID: inst, namespace: id.namespace, vmName: id.vmName, role: id.role, account: acct, accountHome: acctHome,
		expires: now.Add(h.cacheTTL),
		claims: iam.Claims{Sub: "assumed-role/" + id.role + "/" + id.vmName, Groups: groups,
			AssumedRole: dataplaneauthz.QualifiedName(home, id.namespace, id.role), Account: acct}}
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]vmAgent{}
	}
	for k, v := range h.cache { // keep the cache to live entries
		if now.After(v.expires) {
			delete(h.cache, k)
		}
	}
	h.cache[key] = a
	h.mu.Unlock()
	return a, 0, ""
}

// allowed runs the instance role's data-plane check for one of the SSM agent's actions on its instance.
func (h *vmCommandsHandler) allowed(w http.ResponseWriter, r *http.Request, a vmAgent, actions ...string) bool {
	ctx := a.actingIn(r.Context())
	for _, act := range actions {
		if ok, reason := decide(ctx, r, h.authz, a.claims, act, "Instance", a.instanceID,
			scopedDataPlaneOnly(ctx, r, h.authz, a.claims, act, "Instance", a.instanceID)); !ok {
			if h.logger != nil {
				h.logger.Warn("vm-commands: the instance role does not allow "+act, "instance", a.instanceID, "role", a.namespace+"/"+a.role, "reason", reason)
			}
			http.Error(w, "the instance role does not allow "+act+" (attach AmazonSSMManagedInstanceCore): "+reason, http.StatusForbidden)
			return false
		}
	}
	return true
}

func (h *vmCommandsHandler) sweep(ctx context.Context) {
	h.mu.Lock()
	due := time.Since(h.lastSweep) > 30*time.Second
	if due {
		h.lastSweep = time.Now()
	}
	h.mu.Unlock()
	if due {
		_ = h.store.sweep(ctx)
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (h *vmCommandsHandler) poll(w http.ResponseWriter, r *http.Request, a vmAgent) {
	if !h.allowed(w, r, a, "ssm:UpdateInstanceInformation", "ec2messages:GetMessages") {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	m := ssmManagedInstance{InstanceID: a.instanceID, Namespace: a.namespace, VMName: a.vmName, Role: a.role,
		AgentVersion: trunc(q.Get("agentVersion"), 64), PlatformName: trunc(q.Get("platformName"), 128),
		PlatformVersion: trunc(q.Get("platformVersion"), 64), IPAddress: trunc(q.Get("ipAddress"), 64), ComputerName: trunc(q.Get("computerName"), 255)}
	if err := h.store.ping(ctx, m); err != nil {
		http.Error(w, "the SSM store is unavailable; retry", http.StatusServiceUnavailable)
		return
	}
	h.sweep(ctx)
	wait := 0 * time.Second
	if s, err := strconv.Atoi(q.Get("wait")); err == nil && s > 0 {
		wait = time.Duration(s) * time.Second
	}
	if wait > h.maxWait {
		wait = h.maxWait
	}
	woke, done := h.bus.subscribe(a.instanceID)
	defer done()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	recheck := time.NewTicker(h.recheck)
	defer recheck.Stop()
	for {
		cmds, err := h.store.claimPending(ctx, a.instanceID)
		if err != nil {
			http.Error(w, "the SSM store is unavailable; retry", http.StatusServiceUnavailable)
			return
		}
		if len(cmds) > 0 || wait == 0 {
			if cmds == nil {
				cmds = []ssmDelivery{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"InstanceId": a.instanceID, "Commands": cmds})
			return
		}
		select {
		case <-woke:
		case <-recheck.C:
		case <-deadline.C:
			wait = 0 // one last look, then answer empty
		case <-ctx.Done():
			return
		}
	}
}

// ssmAgentResult is what an agent reports for one invocation.
type ssmAgentResult struct {
	Status                string `json:"Status"`
	ResponseCode          int    `json:"ResponseCode"`
	StandardOutputContent string `json:"StandardOutputContent"`
	StandardErrorContent  string `json:"StandardErrorContent"`
}

func (h *vmCommandsHandler) report(w http.ResponseWriter, r *http.Request, a vmAgent, commandID string) {
	if !h.allowed(w, r, a, "ec2messages:SendReply") {
		return
	}
	var res ssmAgentResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res); err != nil {
		http.Error(w, "the report is not JSON", http.StatusBadRequest)
		return
	}
	switch res.Status {
	case "Success", "Failed", "TimedOut":
	default:
		http.Error(w, "Status must be Success, Failed or TimedOut", http.StatusBadRequest)
		return
	}
	err := h.store.finish(r.Context(), commandID, a.instanceID, res.Status, res.ResponseCode, res.StandardOutputContent, res.StandardErrorContent)
	switch {
	case err == errInvocationNotRunning:
		// Not this instance's, not delivered to it, or already ended (timed out, reported): nothing to change.
		http.Error(w, "no invocation of that command is in progress on this instance", http.StatusConflict)
	case err != nil:
		http.Error(w, "the SSM store is unavailable; retry", http.StatusServiceUnavailable)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}
}
