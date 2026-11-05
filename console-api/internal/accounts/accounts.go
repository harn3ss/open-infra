// Package accounts maps Kubernetes namespaces to AWS accounts: the AWS-Organizations model of open-infra,
// where each tenant namespace belongs to one account and every principal, resource and ARN carries that
// account's 12-digit id.
//
// An account is a cluster-scoped kind: Account (organizations.openinfra.dev, platform/abstraction/
// account-xrd.yaml). Its composition labels each of the account's namespaces openinfra.dev/account-id=<id>
// and its home namespace (the first one, where the account's IAM lives) openinfra.dev/account-home=true.
// The labels are the source of truth this package reads, so a lookup never needs the Account objects
// themselves.
//
// The management account is the install's own account (the aws-shim's ACCOUNT_ID, 000000000000 unless
// configured): it keeps every ARN, StackId and queue URL an install has already handed out. A namespace
// that is not labeled and not platform-internal belongs to the management account, so an install behaves
// exactly as before until a namespace is moved into an account of its own.
//
// Platform-internal namespaces (the cluster's own machinery) are never an account's: they are refused at
// admission (the Account XRD's CEL rule, kept in step with PlatformNamespaces by a test) and AccountOf
// returns "" for them.
package accounts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
)

const (
	// LabelAccountID names the account a namespace belongs to.
	LabelAccountID = "openinfra.dev/account-id"
	// LabelAccountHome marks the account's home namespace: where its Users, Groups, Roles and Policies live.
	LabelAccountHome = "openinfra.dev/account-home"
	// LabelAccountStatus is "SUSPENDED" on the namespaces of a suspended account (absent when active).
	LabelAccountStatus = "openinfra.dev/account-status"

	// StatusActive and StatusSuspended are AWS Organizations' account states.
	StatusActive    = "ACTIVE"
	StatusSuspended = "SUSPENDED"

	// DefaultManagementHome is the management account's home namespace: the console's IAM home.
	DefaultManagementHome = "open-infra-console"
)

// PlatformNamespaces are the cluster's own namespaces, never an account's. Kept in step with the Account
// XRD's admission rule (platform/abstraction/account-xrd.yaml) by TestXRDRefusesThePlatformNamespaces.
var PlatformNamespaces = []string{
	"argocd", "cdi", "cert-manager", "chaos-mesh", "cnpg-system", "crossplane-system", "dcgm-exporter",
	"gpu-operator", "keda", "kourier-system", "kubevirt", "kyverno", "lakehouse", "longhorn-system", "mail",
	"mariadb-operator", "metallb-system", "minio", "monitoring", "nats", "nvidia-device-plugin",
	"open-infra-authz", "open-infra-aws-shim", "open-infra-prepull", "redis", "sealed-secrets", "vault",
	"velero",
}

// PlatformPrefixes are name prefixes reserved for platform namespaces.
var PlatformPrefixes = []string{"kube-", "knative-", "openinfra-"}

// ManagementNamespaces are the namespaces the management account holds from the start: the console's IAM
// home and the namespaces the aws-shim's front doors keep their resources in.
var ManagementNamespaces = []string{
	DefaultManagementHome, "open-infra-cfn", "open-infra-ecr", "open-infra-ecs", "open-infra-open-appsync",
	"open-infra-rds", "open-infra-s3",
}

// IsPlatformNamespace reports whether ns is platform-internal (never an account's).
func IsPlatformNamespace(ns string) bool {
	if slices.Contains(PlatformNamespaces, ns) {
		return true
	}
	for _, p := range PlatformPrefixes {
		if strings.HasPrefix(ns, p) {
			return true
		}
	}
	return false
}

var accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)

// ValidAccountID reports whether id is a 12-digit AWS account id.
func ValidAccountID(id string) bool { return accountIDRe.MatchString(id) }

// DeriveAccountID is the account id a new account gets for its home namespace when none is given: "9"
// followed by 11 digits of the namespace's SHA-256 (mod 10^11), so it is stable for a namespace and never
// collides with an AWS-issued id range a site imports as-is (those do not start with 9 by convention here).
// attempt > 0 derives the next candidate, for when the first is taken (see NewAccountID).
func DeriveAccountID(homeNamespace string, attempt int) string {
	in := homeNamespace
	if attempt > 0 {
		in += "#" + strconv.Itoa(attempt)
	}
	sum := sha256.Sum256([]byte(in))
	return fmt.Sprintf("9%011d", binary.BigEndian.Uint64(sum[:8])%100_000_000_000)
}

// NewAccountID is the first derived id for homeNamespace that taken reports free (an account id is
// unique). It gives up after 16 attempts, which only a namespace space of astronomically many accounts
// could exhaust.
func NewAccountID(homeNamespace string, taken func(id string) bool) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		if id := DeriveAccountID(homeNamespace, attempt); !taken(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("no free account id for namespace %s after 16 attempts", homeNamespace)
}

// Directory is the namespace ↔ account map, built from the namespaces' account labels.
type Directory struct {
	management string

	mu        sync.RWMutex
	byNS      map[string]string   // namespace -> account id (labeled namespaces only)
	homes     map[string]string   // account id -> home namespace
	members   map[string][]string // account id -> namespaces, sorted
	suspended map[string]bool     // account id -> suspended
}

// NewDirectory is an empty directory whose management account is management (the install's ACCOUNT_ID;
// "" = iam.ManagementAccount).
func NewDirectory(management string) *Directory {
	if management == "" {
		management = iam.ManagementAccount
	}
	return &Directory{management: management, byNS: map[string]string{}, homes: map[string]string{},
		members: map[string][]string{}, suspended: map[string]bool{}}
}

// Management is the management account's id.
func (d *Directory) Management() string { return d.management }

// IsManagement reports whether account is the management account.
func (d *Directory) IsManagement(account string) bool {
	return account != "" && account == d.management
}

// Observe records namespace ns's account labels (an add or an update); a namespace without an account
// label is forgotten.
func (d *Directory) Observe(ns *corev1.Namespace) {
	if ns == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forgetLocked(ns.Name)
	id := ns.Labels[LabelAccountID]
	if id == "" || IsPlatformNamespace(ns.Name) {
		return
	}
	d.byNS[ns.Name] = id
	members := append(d.members[id], ns.Name)
	sort.Strings(members)
	d.members[id] = members
	if ns.Labels[LabelAccountHome] == "true" {
		d.homes[id] = ns.Name
	}
	if ns.Labels[LabelAccountStatus] == StatusSuspended {
		d.suspended[id] = true
	}
}

// replace makes namespaces the directory's whole view (a fresh listing): one no longer listed is forgotten.
func (d *Directory) replace(namespaces []corev1.Namespace) {
	listed := map[string]bool{}
	for i := range namespaces {
		listed[namespaces[i].Name] = true
		d.Observe(&namespaces[i])
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for name := range d.byNS {
		if !listed[name] {
			d.forgetLocked(name)
		}
	}
}

// Forget removes namespace name (deleted).
func (d *Directory) Forget(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forgetLocked(name)
}

func (d *Directory) forgetLocked(name string) {
	id, ok := d.byNS[name]
	if !ok {
		return
	}
	delete(d.byNS, name)
	d.members[id] = slices.DeleteFunc(d.members[id], func(n string) bool { return n == name })
	if len(d.members[id]) == 0 {
		delete(d.members, id)
		delete(d.suspended, id)
	}
	if d.homes[id] == name {
		delete(d.homes, id)
	}
}

// AccountOf is the account namespace ns belongs to: its label, else the management account for a tenant
// namespace no account has claimed (an install before accounts), and "" for a platform namespace.
func (d *Directory) AccountOf(ns string) string {
	if ns == "" || IsPlatformNamespace(ns) {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if id, ok := d.byNS[ns]; ok {
		return id
	}
	return d.management
}

// Labeled reports whether namespace ns carries an account label (it was placed in an account explicitly).
func (d *Directory) Labeled(ns string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.byNS[ns]
	return ok
}

// HomeOf is account's home namespace: where its IAM objects live and where the aws-shim creates its
// resources. The management account's home defaults to the console's IAM home until a namespace is
// labeled as its home. ok=false for an account the directory does not know.
func (d *Directory) HomeOf(account string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if h, ok := d.homes[account]; ok {
		return h, true
	}
	if d.IsManagement(account) {
		return DefaultManagementHome, true
	}
	return "", false
}

// NamespacesOf lists account's labeled namespaces, sorted.
func (d *Directory) NamespacesOf(account string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return slices.Clone(d.members[account])
}

// Suspended reports whether account is suspended.
func (d *Directory) Suspended(account string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.suspended[account]
}

// Accounts lists the accounts the directory knows: the management account first, then the others by id.
func (d *Directory) Accounts() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := []string{}
	for id := range d.members {
		if id != d.management {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if d.management != "" {
		out = append([]string{d.management}, out...)
	}
	return out
}

// Known reports whether account is the management account or has at least one namespace.
func (d *Directory) Known(account string) bool {
	if d.IsManagement(account) {
		return true
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.members[account]
	return ok
}
