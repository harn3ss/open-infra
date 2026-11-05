package dataplaneauthz

import "github.com/harn3ss/open-infra/console-api/internal/iamauthz"

// The canonical-id rules for IAM objects live in iamauthz (QualifiedName): the bare name in the IAM home
// namespace, "<namespace>/<name>" elsewhere.

// DefaultHomeNamespace is the IAM home namespace when none is configured.
const DefaultHomeNamespace = iamauthz.DefaultHomeNamespace

// QualifiedName is the canonical id of the object ns/name (iamauthz.QualifiedName).
func QualifiedName(home, ns, name string) string { return iamauthz.QualifiedName(home, ns, name) }

// SplitQualified is QualifiedName's inverse (iamauthz.SplitQualified).
func SplitQualified(home, id string) (ns, name string) { return iamauthz.SplitQualified(home, id) }
