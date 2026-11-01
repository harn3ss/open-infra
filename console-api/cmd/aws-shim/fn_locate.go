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
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

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
	cache     map[string]fnLocated
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
	if l == nil || l.dyn == nil || len(l.namespaces) == 0 || name == "" {
		return fallback
	}
	l.mu.Lock()
	if c, ok := l.cache[name]; ok {
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
	for _, n := range l.namespaces {
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
	if len(l.cache) >= fnLocatorCacheMax {
		l.cache = map[string]fnLocated{} // bounded: names come from callers, so start over rather than grow
	}
	l.cache[name] = fnLocated{ns: ns, found: found, at: l.now()}
	l.mu.Unlock()
	if !found {
		return fallback
	}
	return ns
}

// elsewhere reports a namespace other than ns that already has a kind: Function named name ("" none).
func (l *fnLocator) elsewhere(ctx context.Context, name, ns string) (string, error) {
	if l == nil || l.dyn == nil {
		return "", nil
	}
	for _, n := range l.namespaces {
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

// forget drops a remembered answer (a function just created or deleted).
func (l *fnLocator) forget(name string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.cache, name)
	l.mu.Unlock()
}
