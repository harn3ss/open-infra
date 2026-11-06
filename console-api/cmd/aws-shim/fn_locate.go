// Locating a Function by name.
//
// AWS addresses a Lambda function by name (or an ARN carrying only the name) within an account. Here a
// kind: Function lives in one of a few namespaces: the Lambda API's (FUNCTIONS_NAMESPACE) and the one
// CloudFormation stacks deploy into (CFN_NAMESPACE). Every path that invokes a function by name — Lambda
// Invoke and its async (Event) delivery, EventBridge targets, SNS lambda subscriptions, API Gateway
// integrations, a CloudFormation stack's REST API — finds it through this locator, so the FunctionName or
// Arn a stack reports is invocable like one the Lambda API created. (The AppSync Lambda authorizer is one
// configured function in a configured namespace, and Step Functions tasks run in the execution's.)
//
// The locator confirms a kind: Function of that name exists (a Kubernetes Service of the same name is not
// a function, so a crafted name cannot route an invoke to an application). The caller's authority is
// still checked where the function lives: invoking needs `create` on functions in its namespace plus
// lambda:InvokeFunction, as before. When no namespace has it, or the shim cannot read Functions, the
// function is looked for where it always was (the first namespace) — the earlier behavior.
//
// Functions belong to an account, as on AWS. The management account's are in the locator's fixed
// namespaces, exactly as before accounts (namespaceOf, elsewhere and forget answer for it alone). A member
// account's are in its own namespaces — its home first, then the others the account directory lists for
// it — and never in the management account's: namespacesFor, namespaceFor, elsewhereFor and forgetFor
// answer for the request's account, and a member account's function falls back to its home, never to the
// Lambda API's namespace. A door that has not moved to them yet keeps finding the management account's.
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var functionClaimGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "functions"}

const fnLocatorCacheMax = 8192

// fnLocator finds the namespace of the kind: Function named name, among namespaces in order.
type fnLocator struct {
	dyn        dynamic.Interface
	namespaces []string // the first is the default (the Lambda API's)
	logger     *slog.Logger

	hit, miss time.Duration // how long a found / not-found answer is remembered
	now       func() time.Time
	mu        sync.Mutex
	cache     map[string]fnLocated // the management account's, by name
	// memberCache is the member accounts', by accountKey ("<account>:<name>"): apart from cache, so no
	// name a caller passes is ever taken for another account's key.
	memberCache map[string]fnLocated

	// accounts lists a member account's namespaces and knows which accounts exist
	// (internal/accounts.Directory). nil: a member account's functions are in its home alone, and an ARN
	// naming another account is not known to name a member account's function.
	accounts fnAccounts
}

// fnAccounts is what the locator needs of the account directory (internal/accounts.Directory).
type fnAccounts interface {
	NamespacesOf(account string) []string
	Known(account string) bool
}

type fnLocated struct {
	ns    string
	found bool
	at    time.Time
}

func newFnLocator(dyn dynamic.Interface, logger *slog.Logger, namespaces ...string) *fnLocator {
	seen := map[string]bool{}
	var ns []string
	for _, n := range namespaces {
		if n != "" && !seen[n] {
			seen[n] = true
			ns = append(ns, n)
		}
	}
	return &fnLocator{dyn: dyn, namespaces: ns, logger: logger, hit: time.Minute, miss: 5 * time.Second,
		now: time.Now, cache: map[string]fnLocated{}}
}

// namespaceOf is the namespace whose kind: Function is named name. A function in more than one of them
// resolves to the first (the Lambda API's namespace first): CloudFormation refuses to create a function
// whose name another namespace has, so only functions made before that rule can collide. Not found, or
// not readable, falls back to the first namespace. A nil locator answers fallback.
func (l *fnLocator) namespaceOf(ctx context.Context, name, fallback string) string {
	if l == nil {
		return fallback
	}
	return l.locate(ctx, false, name, name, l.namespaces, fallback)
}

// namespacesFor is the namespaces the request's account keeps its functions in: the locator's own (the
// Lambda API's first) for the management account; for a member account its home, then the other
// namespaces the account directory lists for it — never one of the management account's, whatever a label
// says. A member request with neither a home nor a listed namespace has none.
func (l *fnLocator) namespacesFor(ctx context.Context) []string {
	if !isMemberRequest(ctx) {
		if l == nil {
			return nil
		}
		return l.namespaces
	}
	seen := map[string]bool{}
	if l != nil {
		for _, n := range l.namespaces {
			seen[n] = true
		}
	}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	home, _ := ctx.Value(accountHomeKey{}).(string)
	add(home)
	if l != nil && l.accounts != nil {
		for _, n := range l.accounts.NamespacesOf(callerAccount(ctx)) {
			add(n)
		}
	}
	return out
}

// namespaceFor is namespaceOf for the request's account: for the management account exactly namespaceOf
// (fallback when not found); for a member account the namespace among its own (namespacesFor) whose
// kind: Function is named name, else the first of them (its home) — never fallback, the management
// account's. A member account with no namespace gets one that names none (noFnNamespace).
func (l *fnLocator) namespaceFor(ctx context.Context, name, fallback string) string {
	if !isMemberRequest(ctx) {
		return l.namespaceOf(ctx, name, fallback)
	}
	own := l.namespacesFor(ctx)
	if len(own) == 0 {
		return noFnNamespace
	}
	return l.locate(ctx, true, accountKey(ctx, name), name, own, own[0])
}

// noFnNamespace is the namespace of a member account that has none: never a Kubernetes namespace, so
// nothing is found, read or invoked there.
const noFnNamespace = "\x00no-namespace"

// memberAccount reports whether account is a member account the directory knows: an ARN naming it names
// that account's function, never the management account's function of the same name.
func (l *fnLocator) memberAccount(account string) bool {
	return l != nil && l.accounts != nil && account != "" && !awsidentity.Current().IsManagement(account) &&
		l.accounts.Known(account)
}

// locate finds which of namespaces has the kind: Function named name, remembering the answer under key
// (in the member accounts' cache when member, else the management account's); fallback when none has it
// or one could not be read.
func (l *fnLocator) locate(ctx context.Context, member bool, key, name string, namespaces []string, fallback string) string {
	if l == nil || l.dyn == nil || len(namespaces) == 0 || name == "" {
		return fallback
	}
	l.mu.Lock()
	if c, ok := l.cacheOf(member)[key]; ok {
		ttl := l.miss
		if c.found {
			ttl = l.hit
		}
		if l.now().Sub(c.at) < ttl {
			l.mu.Unlock()
			if c.found {
				return c.ns
			}
			return fallback
		}
	}
	l.mu.Unlock()

	ns, found, unreadable := "", false, false
	for _, n := range namespaces {
		ok, err := l.exists(ctx, n, name)
		if err != nil {
			// Unreadable (e.g. the shim may not read Functions there): look on, and remember nothing.
			unreadable = true
			if l.logger != nil {
				l.logger.Debug("function lookup failed", "function", name, "namespace", n, "error", err.Error())
			}
			continue
		}
		if ok {
			ns, found = n, true
			break
		}
	}
	if !found && unreadable {
		return fallback
	}
	l.mu.Lock()
	if member {
		if len(l.memberCache) >= fnLocatorCacheMax || l.memberCache == nil {
			l.memberCache = map[string]fnLocated{} // bounded, as the management account's
		}
		l.memberCache[key] = fnLocated{ns: ns, found: found, at: l.now()}
	} else {
		if len(l.cache) >= fnLocatorCacheMax {
			l.cache = map[string]fnLocated{} // bounded: names come from callers, so start over rather than grow
		}
		l.cache[key] = fnLocated{ns: ns, found: found, at: l.now()}
	}
	l.mu.Unlock()
	if !found {
		return fallback
	}
	return ns
}

// cacheOf is the remembered answers of the member accounts (keyed "<account>:<name>") or of the management
// account (keyed by name). They are kept apart so that no name a caller passes can be taken for another
// account's key. l.mu is held.
func (l *fnLocator) cacheOf(member bool) map[string]fnLocated {
	if member {
		return l.memberCache
	}
	return l.cache
}

// elsewhere reports a namespace other than ns that already has a kind: Function named name ("" none),
// among the management account's namespaces.
func (l *fnLocator) elsewhere(ctx context.Context, name, ns string) (string, error) {
	if l == nil {
		return "", nil
	}
	return l.elsewhereIn(ctx, name, ns, l.namespaces)
}

// elsewhereFor is elsewhere among the request's account's namespaces (namespacesFor): a name is unique
// within an account, and another account's function of the same name is no collision.
func (l *fnLocator) elsewhereFor(ctx context.Context, name, ns string) (string, error) {
	if l == nil {
		return "", nil
	}
	return l.elsewhereIn(ctx, name, ns, l.namespacesFor(ctx))
}

func (l *fnLocator) elsewhereIn(ctx context.Context, name, ns string, namespaces []string) (string, error) {
	if l == nil || l.dyn == nil {
		return "", nil
	}
	for _, n := range namespaces {
		if n == ns {
			continue
		}
		ok, err := l.exists(ctx, n, name)
		if err != nil {
			return "", err
		}
		if ok {
			return n, nil
		}
	}
	return "", nil
}

func (l *fnLocator) exists(ctx context.Context, ns, name string) (bool, error) {
	_, err := l.dyn.Resource(functionClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// forget drops a remembered answer (a function just created or deleted) of the management account.
func (l *fnLocator) forget(name string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.cache, name)
	l.mu.Unlock()
}

// forgetFor is forget for the request's account's function named name.
func (l *fnLocator) forgetFor(ctx context.Context, name string) {
	if !isMemberRequest(ctx) {
		l.forget(name)
		return
	}
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.memberCache, accountKey(ctx, name))
	l.mu.Unlock()
}
