// CloudFormation keeps each account's stacks apart, as AWS does: a stack belongs to the account that made it,
// its name is unique within that account, its StackId names that account, and no other account lists,
// reads or changes it.
//
//   - The management account's stacks stay exactly where they always were: their resources in the stack
//     namespace (CFN_NAMESPACE), their records under the names they always had, their StackIds and change-set
//     ARNs naming the install's account. A member account's stacks are kept beside them: their resources in
//     the member account's home namespace (written as the caller, whose RBAC the IAM compiler generates
//     there), their StackIds and change-set ARNs naming the member account.
//   - The records stay in the record store (the shim's own namespace, where it already keeps Secrets). A
//     member account's are named "<account>-<name>" and labelled openinfra.dev/account-id: a name no
//     management-account record has (those begin "cfn-" or "noecho-"), so neither account's names can reach
//     the other's. Every read goes through accountRecords, which translates the names and keeps each
//     listing to its own account's records.
//   - The queues, topics, parameters, keys and aliases a stack provisions are stored under the account's
//     key in their front doors' stores (accountKey), and the record of which stack made each one carries
//     its account (cfn_service_resources' account column).
//   - Work that runs without a request — a stack operation in the background, the recovery pass, a
//     WaitConditionHandle signal — acts in the account its stack record (or the signed handle URL) names.
package main

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

func init() { accountScopedServices["cloudformation"] = true }

// labelRecordAccount labels a member account's records with its account. The management account's records
// carry none (they are exactly what they always were).
const labelRecordAccount = "openinfra.dev/account-id"

// memberRecordRe matches a member account's record name ("<12-digit account>-<name>").
var memberRecordRe = regexp.MustCompile(`^[0-9]{12}-.`)

// accountHomeOf is the home namespace the request's member account acts in ("" for the management account,
// or a member account the router found no home for).
func accountHomeOf(ctx context.Context) string {
	home, _ := ctx.Value(accountHomeKey{}).(string)
	return home
}

// accountFor is the account a CloudFormation request acts in, as its StackIds and ARNs name it: the
// doorway's own (h.account, exactly as before) for the management account, the member account's id for one
// of its requests.
func (h *cfnDoorway) accountFor(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// nsFor is the namespace a request's stacks are kept in: the stack namespace for the management account,
// the member account's home for a member's (accountNamespace).
func (h *cfnDoorway) nsFor(ctx context.Context) string { return accountNamespace(ctx, h.ns) }

// recsFor is the record store of the request's account: the management account's records (recs), or a
// member account's, kept beside them under its own names.
func (h *cfnDoorway) recsFor(ctx context.Context) recordStore {
	st := h.recs()
	if isMemberRequest(ctx) {
		st.account = callerAccount(ctx)
	}
	return st
}

// identityFor is the identity the request's stacks are made in: its account, the doorway's region, and the
// namespace its stacks are kept in (the StackId derives from it).
func (h *cfnDoorway) identityFor(ctx context.Context) awsidentity.Identity {
	return awsidentity.Identity{AccountID: h.accountFor(ctx), Region: h.region, StackNamespace: h.nsFor(ctx)}
}

// opKey is the key a stack's operation is tracked under in this process (cfnOps): its name for the
// management account's stack, "<account>:<name>" for a member's — so two accounts' stacks of one name are two
// stacks (a stack name has no ":").
func (h *cfnDoorway) opKey(ctx context.Context, stack string) string { return accountKey(ctx, stack) }

// inAccount is ctx acting in account (with home): what the router puts on a request of that account, for work
// that runs without one. The management account's work keeps ctx exactly as it is.
func inAccount(ctx context.Context, account, home string) context.Context {
	if awsidentity.Current().IsManagement(account) {
		return ctx
	}
	return inAccountScope(withAccount(ctx, account, home))
}

// accountCtx is ctx acting in the account this applier was built for (a stack operation's own account),
// for the operation's work in the background.
func (a *impersonatingApplier) accountCtx(ctx context.Context) context.Context {
	if a == nil || a.account == "" {
		return ctx
	}
	return inAccount(ctx, a.account, a.home)
}

// opKey is cfnDoorway.opKey for the account this applier acts in.
func (a *impersonatingApplier) opKey(stack string) string {
	if a == nil || a.account == "" {
		return stack
	}
	return a.account + ":" + stack
}

// homeOf is the home namespace of member account account: the accounts directory's, else (no directory —
// a doorway built without one) fallback. ok=false when the directory knows no home for it.
func (h *cfnDoorway) homeOf(account, fallback string) (string, bool) {
	if h.accounts == nil {
		return fallback, fallback != ""
	}
	home, ok := h.accounts.HomeOf(account)
	return home, ok && home != ""
}

// --- the record store's names ---

// physicalRecordName is the name a record of account is stored under: its own name for the management
// account's (""), "<account>-<name>" for a member account's.
func physicalRecordName(account, name string) string {
	if account == "" {
		return name
	}
	return account + "-" + name
}

// recordAccountOf is the account a stored record belongs to ("" the management account) and its name within
// that account; ok=false for a record that is neither account's as stored (a member name without its label,
// or a label naming another account than its name).
func recordAccountOf(u *unstructured.Unstructured) (account, name string, ok bool) {
	name = u.GetName()
	account = u.GetLabels()[labelRecordAccount]
	if account == "" {
		return "", name, !memberRecordRe.MatchString(name)
	}
	if !strings.HasPrefix(name, account+"-") || len(name) == len(account)+1 {
		return "", "", false
	}
	return account, name[len(account)+1:], true
}

// accountRecords is a record store's client for one account's records: a member account's are stored
// under their physical names and labelled with their account, and read back by the names they have within
// the account; a listing returns that account's records alone (the management account's never include a
// member account's, nor a member's another account's).
type accountRecords struct {
	dynamic.ResourceInterface
	account string // "" = the management account
}

var errRecordsNoWatch = errors.New("a member account's records cannot be watched")

func (c accountRecords) physical(name string) string { return physicalRecordName(c.account, name) }

// own reports whether a stored record is this account's, and its name within the account.
func (c accountRecords) own(u *unstructured.Unstructured) (string, bool) {
	account, name, ok := recordAccountOf(u)
	if !ok || account != c.account {
		return "", false
	}
	return name, true
}

// toStore is obj as stored: a member account's under its physical name, with its account label.
func (c accountRecords) toStore(obj *unstructured.Unstructured) *unstructured.Unstructured {
	if c.account == "" || obj == nil {
		return obj
	}
	out := obj.DeepCopy()
	out.SetName(c.physical(obj.GetName()))
	labels := out.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[labelRecordAccount] = c.account
	out.SetLabels(labels)
	return out
}

// fromStore is a stored record as the account reads it (by its name within the account).
func (c accountRecords) fromStore(u *unstructured.Unstructured, err error) (*unstructured.Unstructured, error) {
	if err != nil || u == nil || c.account == "" {
		return u, err
	}
	name, ok := c.own(u)
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "records"}, u.GetName())
	}
	u.SetName(name)
	return u, nil
}

func (c accountRecords) Create(ctx context.Context, obj *unstructured.Unstructured, opts metav1.CreateOptions, sub ...string) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.Create(ctx, c.toStore(obj), opts, sub...))
}

func (c accountRecords) Update(ctx context.Context, obj *unstructured.Unstructured, opts metav1.UpdateOptions, sub ...string) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.Update(ctx, c.toStore(obj), opts, sub...))
}

func (c accountRecords) UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, opts metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.UpdateStatus(ctx, c.toStore(obj), opts))
}

func (c accountRecords) Delete(ctx context.Context, name string, opts metav1.DeleteOptions, sub ...string) error {
	return c.ResourceInterface.Delete(ctx, c.physical(name), opts, sub...)
}

func (c accountRecords) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return c.ResourceInterface.DeleteCollection(ctx, opts, c.selector(listOpts))
}

func (c accountRecords) Get(ctx context.Context, name string, opts metav1.GetOptions, sub ...string) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.Get(ctx, c.physical(name), opts, sub...))
}

// selector keeps a member account's listing to its own records (the listing is filtered again as read).
func (c accountRecords) selector(opts metav1.ListOptions) metav1.ListOptions {
	if c.account == "" {
		return opts
	}
	sel := labelRecordAccount + "=" + c.account
	if opts.LabelSelector != "" {
		sel = opts.LabelSelector + "," + sel
	}
	opts.LabelSelector = sel
	return opts
}

func (c accountRecords) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	list, err := c.ResourceInterface.List(ctx, c.selector(opts))
	if err != nil || list == nil {
		return list, err
	}
	kept := make([]unstructured.Unstructured, 0, len(list.Items))
	for i := range list.Items {
		u := list.Items[i]
		name, ok := c.own(&u)
		if !ok {
			continue
		}
		u.SetName(name)
		kept = append(kept, u)
	}
	list.Items = kept
	return list, nil
}

func (c accountRecords) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	if c.account != "" {
		return nil, errRecordsNoWatch
	}
	return c.ResourceInterface.Watch(ctx, opts)
}

func (c accountRecords) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, sub ...string) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.Patch(ctx, c.physical(name), pt, data, opts, sub...))
}

func (c accountRecords) Apply(ctx context.Context, name string, obj *unstructured.Unstructured, opts metav1.ApplyOptions, sub ...string) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.Apply(ctx, c.physical(name), c.toStore(obj), opts, sub...))
}

func (c accountRecords) ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, opts metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return c.fromStore(c.ResourceInterface.ApplyStatus(ctx, c.physical(name), c.toStore(obj), opts))
}

// --- every account's records, for work without a request ---

// recordAccounts is ctx for each account that has records in the store: the management account's (ctx
// itself) first, then each member account's (acting in it, with its home when the directory knows one) —
// so a pass over the records (pruning deleted stacks) covers every account, each within its own records.
func (h *cfnDoorway) recordAccounts(ctx context.Context) []context.Context {
	out := []context.Context{ctx}
	list, err := h.recs().rawClient().List(ctx, metav1.ListOptions{LabelSelector: labelRecordAccount})
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	for i := range list.Items {
		account, _, ok := recordAccountOf(&list.Items[i])
		if !ok || account == "" || seen[account] {
			continue
		}
		seen[account] = true
		home, _ := h.homeOf(account, "")
		out = append(out, inAccount(ctx, account, home))
	}
	return out
}
