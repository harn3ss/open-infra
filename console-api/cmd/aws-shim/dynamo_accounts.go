// DynamoDB and DynamoDB Streams keep each account's tables apart, as AWS does: a table belongs to the
// account that created it, its name is unique within that account, its ARN and its stream's ARN name that
// account, and no other account sees it, reads it or lists it.
//
// The management account's tables are exactly where they always were: a table's collection, its registry
// entry (the _shim_dynamo_tables _id) and its stream's rows (ddbstream_streams / ddbstream_records
// table_name) are keyed by the table's name. A member account's are keyed by accountKey,
// "<account>:<name>", beside them. ":" is in no DynamoDB table name ([a-zA-Z0-9_.-]+, and a name with one
// is refused), so a member account's key never equals a management table's name nor another member's
// key. FerretDB (on documentdb) takes ":" in a collection name, in the mongo wire and in the documentdb_api
// calls the transactions make; it caps the whole namespace (database "." collection) at 235 bytes, so a
// member account's table name has 13 characters less room than the management account's.
//
// The names are mapped at the edge. serve decides authorization on the names the request carries (as AWS
// decides on the table's ARN in the caller's account), then turns each into the caller's account's key; every
// name a response or an error message carries is the key with the account taken off (tableName). The
// background paths work on keys alone: the TTL reaper sweeps each registry entry's own collection, and the
// declared-table sync keys a kind: Table by the account of the namespace its claim is in.
package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	// DynamoDB Streams is signed for "dynamodb" (the router hands it to its own door); its door key is
	// "dynamodbstreams", which is how an in-process call names it.
	accountScopedServices["dynamodb"] = true
	accountScopedServices["dynamodbstreams"] = true
}

// tableNameRefusal is AWS's ValidationException message for a table name with ":" in it ("" for any other
// name). AWS allows [a-zA-Z0-9_.-]+; the shim refuses only ":", the one character that could make a name
// one account's key in another's — every other name it accepted before it still accepts.
func tableNameRefusal(name string) string {
	if !strings.Contains(name, ":") {
		return ""
	}
	return "1 validation error detected: Value '" + name + "' at 'tableName' failed to satisfy constraint: " +
		"Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
}

// scopeDynamoRequest turns every table name a DynamoDB request carries into the caller's account's key
// (accountKey) — TableName, the RequestItems of a batch, each TransactItem's TableName, a restore's source
// and target — and returns the request's table key, with AWS's validation message when a name is refused
// ("" when every name is valid). The management account's names are their own keys, so its requests are
// left exactly as they came. ListTables' ExclusiveStartTableName is validated here and keyed by listTables.
func scopeDynamoRequest(ctx context.Context, op, table string, body map[string]any) (key, refusal string) {
	scope := func(name string) string {
		if r := tableNameRefusal(name); r != "" && refusal == "" {
			refusal = r
		}
		return accountKey(ctx, name)
	}
	if table != "" {
		key = scope(table)
		body["TableName"] = key
	}
	switch op {
	case "ListTables":
		if start, _ := body["ExclusiveStartTableName"].(string); start != "" {
			_ = scope(start)
		}
	case "BatchGetItem", "BatchWriteItem":
		if items, ok := body["RequestItems"].(map[string]any); ok {
			scoped := make(map[string]any, len(items))
			for t, spec := range items {
				scoped[scope(t)] = spec
			}
			body["RequestItems"] = scoped
		}
	case "TransactGetItems", "TransactWriteItems":
		list, _ := body["TransactItems"].([]any)
		for _, e := range list {
			it, _ := e.(map[string]any)
			for _, k := range dynamoTxnKinds {
				if m, ok := it[k.kind].(map[string]any); ok {
					if t, _ := m["TableName"].(string); t != "" {
						m["TableName"] = scope(t)
					}
				}
			}
		}
	case "RestoreTableToPointInTime":
		for _, f := range []string{"SourceTableName", "TargetTableName"} {
			if t, _ := body[f].(string); t != "" {
				body[f] = scope(t)
			}
		}
	}
	return key, refusal
}

// tableName is the name the caller knows a table by: its key with the caller's account taken off (the
// management account's keys are their names).
func tableName(ctx context.Context, key string) string {
	if name, ok := nameOfAccountKey(ctx, key); ok {
		return name
	}
	return key
}

// arnAccount is the account a table's ARNs carry: the member account the request acts in, else the
// install's own (h.account, as every management-account ARN always carried).
func (h *dynamoHandler) arnAccount(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// arnAccount is the account a stream's ARN carries (dynamoHandler.arnAccount's twin for the Streams door).
func (h *ddbStreamsHandler) arnAccount(ctx context.Context) string {
	if isMemberRequest(ctx) {
		return callerAccount(ctx)
	}
	return h.account
}

// dynamoTableARN renders arn:aws:dynamodb:<region>:<account>:table/<table>, the TableArn AWS reports.
func dynamoTableARN(region, account, table string) string {
	return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, account, table)
}

// tableKeyIDFilter is the registry _id range a ListTables reads for the caller's account, after start (a
// table name; "" from the first): a member account's keys are exactly those between "<account>:" and
// "<account>;" (";" follows ":"), the management account's are every key, of which the listing keeps
// those that are not a member account's (nameOfAccountKey).
func tableKeyIDFilter(ctx context.Context, start string) map[string]any {
	f := map[string]any{}
	if isMemberRequest(ctx) {
		f["$lt"] = callerAccount(ctx) + ";"
		if start == "" {
			f["$gt"] = callerAccount(ctx) + ":"
		}
	}
	if start != "" {
		f["$gt"] = accountKey(ctx, start)
	}
	return f
}

// accountIDRe is a member account's id as namespaces are labelled with it.
var accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)

// tableAccounts maps a namespace placed in a member account (its openinfra.dev/account-id label) to that
// account: the account a kind: Table declared in that namespace belongs to. A namespace in no member
// account — unlabelled, a platform namespace, or labelled with the management account — is the management
// account's, as the account directory places it. A label that is no account id is in bad: a declaration
// there is no account's, and is left unregistered rather than taken for the management account's.
type tableAccounts struct {
	member map[string]string
	bad    map[string]bool
}

// declaredTableAccounts lists the namespaces placed in an account. It reads the namespaces' labels itself
// rather than the router's directory, which until its first listing places every namespace in the
// management account: the sync would register a member account's table as the management account's.
func (h *dynamoHandler) declaredTableAccounts(ctx context.Context) (tableAccounts, error) {
	ta := tableAccounts{member: map[string]string{}, bad: map[string]bool{}}
	l, err := h.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: accounts.LabelAccountID})
	if err != nil {
		return ta, err
	}
	mgmt := awsidentity.Current()
	for _, ns := range l.Items {
		id := ns.Labels[accounts.LabelAccountID]
		switch {
		case accounts.IsPlatformNamespace(ns.Name) || mgmt.IsManagement(id):
		case accountIDRe.MatchString(id):
			ta.member[ns.Name] = id
		default:
			ta.bad[ns.Name] = true
		}
	}
	return ta, nil
}

// of is the account a table declared in namespace ns belongs to (ok=false: none — its label is no account id).
func (ta tableAccounts) of(ns string) (account string, ok bool) {
	if ta.bad[ns] {
		return "", false
	}
	if id, member := ta.member[ns]; member {
		return id, true
	}
	return awsidentity.Current().AccountID, true
}

// tableNamespaceLabel is the label the Table composition puts on a declaration: the namespace of its claim.
const tableNamespaceLabel = "openinfra.dev/table-namespace"
