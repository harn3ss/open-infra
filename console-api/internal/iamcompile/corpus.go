// Package iamcompile compiles IAM policy — the one place authority is written — into what Kubernetes
// still enforces underneath: a Cedar control-plane corpus for the account-qualified principals the
// console and the aws-shim impersonate ("openinfra:<account>:<user>"), and generated RBAC for the
// paths where the API server's own RBAC still decides. It is the reverse of rbac-to-cedar: IAM is
// the source and RBAC is generated from it, never the other way round.
//
// Never widen: what RBAC cannot express exactly — a Deny, a condition, a NotAction or NotResource, a
// resource pattern that is neither "every name" nor a literal name — is dropped from the RBAC side
// (narrower) and reported. The Cedar side keeps Deny statements, applying a conditional Deny
// unconditionally (narrower), and drops a conditional Allow (narrower), since a control-plane request
// carries none of the condition keys IAM documents use.
package iamcompile

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

const (
	// CorpusNamespace / CorpusName / CorpusKey locate the compiled iam-corpus, beside the RBAC-derived
	// control-plane-corpus the webhook already loads.
	CorpusNamespace = "open-infra-authz"
	CorpusName      = "iam-corpus"
	CorpusKey       = "corpus.yaml"
)

var configMapGVR = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}

// accountUser matches the account-qualified identity a console or shim principal acts as once IAM
// policy is the authority (iam.AccountIdentity): "openinfra:<12-digit account>:<principal>".
var accountUser = regexp.MustCompile(`^openinfra:[0-9]{12}:.+`)

// IsAccountIdentity reports whether a Kubernetes username is an account-qualified IAM principal, the
// principals the iam-corpus is authoritative for.
func IsAccountIdentity(user string) bool { return accountUser.MatchString(user) }

// Grant is one corpus entry: the principals it applies to and its control-plane statements, in the
// same shape as the control-plane-corpus bundle (controlplaneauthz parses both). Caveats record what
// compiling dropped or narrowed, for review; the loader ignores them.
type Grant struct {
	AppliesTo  []string    `json:"appliesTo"`
	Caveats    []string    `json:"caveats,omitempty"`
	Statements []Statement `json:"statements"`
}

// Statement is one control-plane statement: Kubernetes verbs on "<resource>.<group>::<id>" resources.
type Statement struct {
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// MarshalCorpus renders grants as the corpus document, deterministically (sorted by principal).
func MarshalCorpus(grants []Grant) ([]byte, error) {
	sorted := append([]Grant(nil), grants...)
	sort.SliceStable(sorted, func(i, j int) bool { return first(sorted[i].AppliesTo) < first(sorted[j].AppliesTo) })
	if sorted == nil {
		sorted = []Grant{}
	}
	return yaml.Marshal(sorted)
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// ParseCorpus decodes an iam-corpus document into the control-plane policy docs the webhook evaluates.
func ParseCorpus(raw []byte) ([]controlplaneauthz.PolicyDoc, error) {
	var grants []Grant
	if err := yaml.Unmarshal(raw, &grants); err != nil {
		return nil, fmt.Errorf("%s/%s key %q: %w", CorpusNamespace, CorpusName, CorpusKey, err)
	}
	var docs []controlplaneauthz.PolicyDoc
	for _, g := range grants {
		doc := controlplaneauthz.PolicyDoc{AppliesTo: g.AppliesTo}
		for _, s := range g.Statements {
			doc.Statements = append(doc.Statements, policyengine.Statement{
				Effect:    policyengine.Effect(s.Effect),
				Actions:   s.Actions,
				Resources: s.Resources,
			})
		}
		if len(doc.Statements) > 0 {
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

// CorpusLoader reads the iam-corpus ConfigMap for the authorization webhook. A missing ConfigMap is not
// an error: it is "no corpus", which the webhook treats as deferring to RBAC (the generated bindings).
func CorpusLoader(dc dynamic.Interface) controlplaneauthz.Loader {
	return func(ctx context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		cm, err := dc.Resource(configMapGVR).Namespace(CorpusNamespace).Get(ctx, CorpusName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		data, _ := cm.Object["data"].(map[string]any)
		raw, _ := data[CorpusKey].(string)
		if raw == "" {
			return nil, nil
		}
		return ParseCorpus([]byte(raw))
	}
}
