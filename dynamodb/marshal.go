package dynamodb

import (
	"fmt"
	"strconv"
)

// ToDynamoDB is the inverse of fromDynamoDB: a plain Go value → a DynamoDB-typed attribute value
// ({"S":…}/{"N":"…"}/{"BOOL":…}/{"NULL":true}/{"L":[…]}/{"M":{…}}). The store operates in plain-value
// space; the aws-shim's DynamoDB front door needs to re-dress a result as the typed envelopes the
// wire protocol (and an unmodified AWS SDK) expects. Numbers are wire-encoded as strings, as
// DynamoDB does.
func ToDynamoDB(v any) map[string]any {
	switch x := v.(type) {
	case nil:
		return map[string]any{"NULL": true}
	case string:
		return map[string]any{"S": x}
	case bool:
		return map[string]any{"BOOL": x}
	case float64:
		return map[string]any{"N": strconv.FormatFloat(x, 'f', -1, 64)}
	case int:
		return map[string]any{"N": strconv.Itoa(x)}
	case int64:
		return map[string]any{"N": strconv.FormatInt(x, 10)}
	case []any:
		list := make([]any, len(x))
		for i, e := range x {
			list[i] = ToDynamoDB(e)
		}
		return map[string]any{"L": list}
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = ToDynamoDB(e)
		}
		return map[string]any{"M": m}
	default:
		// Unknown Go type — represent as a string rather than dropping it (never a silent loss).
		return map[string]any{"S": fmt.Sprint(x)}
	}
}

// ToItem marshals a plain item map into a DynamoDB-typed Item (attribute name → typed value).
func ToItem(item map[string]any) map[string]any {
	out := make(map[string]any, len(item))
	for k, v := range item {
		out[k] = ToDynamoDB(v)
	}
	return out
}
