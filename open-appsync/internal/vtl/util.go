package vtl

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The AppSync `$util` helper library — the part of VTL fidelity that "lives or dies".
// A resolver's templating can be perfect, but if the $util helpers are wrong every real-world
// resolver breaks. The DynamoDB typed-JSON conversion below is the single most important helper for
// slice 1; its shape ({"S":…}/{"N":…}/{"M":…}/…) is fixed by AWS's documented behavior and is the
// probe's ground truth.
//
// autoId and time.* are non-deterministic; they take injectable providers so a probe can pin them
// and assert byte-exact output (the same discipline as the workflow-script clock ban).

// ThrowError is what $util.error/$util.appendError raise — it aborts template rendering with the
// AppSync error shape (message + errorType), mirroring how AppSync surfaces a resolver-thrown error.
type ThrowError struct {
	Message   string
	ErrorType string
	Data      any
}

func (e *ThrowError) Error() string { return e.Message }

// Util is the $util namespace. Providers default to real implementations; tests override them.
type Util struct {
	AutoID func() string    // $util.autoId()
	Now    func() time.Time // $util.time.*
}

// NewUtil returns a $util with real providers (crypto-random v4-ish ID, wall clock).
func NewUtil() *Util {
	return &Util{AutoID: newUUID, Now: time.Now}
}

// call dispatches a `$util.<path>(args)` invocation. ok=false means "no such $util method" so the
// caller can report an honest error rather than silently returning nil.
func (u *Util) call(path string, args []any) (result any, err error, ok bool) {
	switch path {
	case "toJson", "toJsonString":
		return jsonString(arg(args, 0)), nil, true
	case "parseJson":
		var v any
		if s, isStr := arg(args, 0).(string); isStr {
			_ = json.Unmarshal([]byte(s), &v)
		}
		return v, nil, true
	case "autoId":
		return u.AutoID(), nil, true
	case "time.nowISO8601":
		return u.Now().UTC().Format("2006-01-02T15:04:05.000Z"), nil, true
	case "time.nowEpochSeconds":
		return float64(u.Now().Unix()), nil, true
	case "time.nowEpochMilliSeconds":
		return float64(u.Now().UnixMilli()), nil, true
	case "isNull":
		return arg(args, 0) == nil, nil, true
	case "isNullOrEmpty":
		return isNullOrEmpty(arg(args, 0)), nil, true
	case "isNullOrBlank":
		s, _ := arg(args, 0).(string)
		return arg(args, 0) == nil || strings.TrimSpace(s) == "", nil, true
	case "defaultIfNull":
		if arg(args, 0) == nil {
			return arg(args, 1), nil, true
		}
		return arg(args, 0), nil, true
	case "defaultIfNullOrEmpty":
		if isNullOrEmpty(arg(args, 0)) {
			return arg(args, 1), nil, true
		}
		return arg(args, 0), nil, true
	case "matches":
		re, rerr := regexp.Compile(toStr(arg(args, 0)))
		if rerr != nil {
			return false, nil, true
		}
		return re.MatchString(toStr(arg(args, 1))), nil, true
	case "error":
		return nil, &ThrowError{Message: toStr(arg(args, 0)), ErrorType: toStr(arg(args, 1)), Data: arg(args, 2)}, true
	case "appendError":
		return "", &ThrowError{Message: toStr(arg(args, 0)), ErrorType: toStr(arg(args, 1)), Data: arg(args, 2)}, true
	case "dynamodb.toDynamoDBJson":
		return jsonString(toDynamoDB(arg(args, 0))), nil, true
	case "dynamodb.toMapValuesJson":
		return jsonString(toMapValues(arg(args, 0))), nil, true
	case "dynamodb.toString", "dynamodb.toStringJson":
		return jsonString(map[string]any{"S": toStr(arg(args, 0))}), nil, true
	case "dynamodb.toNumber", "dynamodb.toNumberJson":
		n, _ := toNum(arg(args, 0))
		return jsonString(map[string]any{"N": n}), nil, true
	case "dynamodb.toBoolean", "dynamodb.toBooleanJson":
		return jsonString(map[string]any{"BOOL": truthy(arg(args, 0))}), nil, true
	}
	return nil, nil, false
}

// Call invokes a $util method by path (e.g. "toJson", "autoId", "time.nowISO8601") for a runtime that
// is NOT VTL — the JS runtime reuses this exact dispatcher so the two runtimes can never drift. A
// $util.error surfaces as a *ThrowError; an unknown path is an error.
func (u *Util) Call(path string, args []any) (any, error) {
	res, err, ok := u.call(path, args)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("util: unknown method %q", path)
	}
	return res, nil
}

// ToDynamoDB / ToMapValues expose the DynamoDB typed marshalling as OBJECTS (not JSON strings) for the
// JS runtime, which builds operation objects directly rather than interpolating strings into a
// template. Same underlying conversion as $util.dynamodb.toDynamoDBJson — one implementation, no drift.
func (u *Util) ToDynamoDB(v any) any             { return toDynamoDB(v) }
func (u *Util) ToMapValues(v any) map[string]any { return toMapValues(v) }

// toDynamoDB converts a plain value to its DynamoDB typed representation ({"S":…} etc.), recursively.
// This is the ground-truth shape from AWS's docs — the heart of DynamoDB resolver fidelity.
func toDynamoDB(v any) any {
	switch x := v.(type) {
	case nil:
		// AppSync emits NULL as JSON `null` (verified against real AppSync), NOT the DynamoDB SDK's
		// `{"NULL": true}`. open-appsync matches AppSync, since that is what a resolver author's
		// existing templates were written against.
		return map[string]any{"NULL": nil}
	case string:
		return map[string]any{"S": x}
	case bool:
		return map[string]any{"BOOL": x}
	// AppSync emits N as a JSON number (verified against real AppSync), NOT the DynamoDB SDK's
	// stringified `{"N": "36"}`. AppSync converts it to the wire string internally.
	case float64:
		return map[string]any{"N": x}
	case int:
		return map[string]any{"N": x}
	case int64:
		return map[string]any{"N": x}
	case []any:
		list := make([]any, len(x))
		for i, e := range x {
			list[i] = toDynamoDB(e)
		}
		return map[string]any{"L": list}
	case map[string]any:
		return map[string]any{"M": toMapValues(x)}
	default:
		return map[string]any{"S": toStr(v)}
	}
}

// toMapValues converts a map to a DynamoDB attribute-values map: {k: {"S":…}, …}.
func toMapValues(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		out[k] = toDynamoDB(val)
	}
	return out
}

func isNullOrEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// jsonString marshals a value to a compact, DETERMINISTIC JSON string (encoding/json sorts map
// keys), so probe output is byte-stable.
func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// numStr renders a number the way DynamoDB/AppSync expect: integers without a trailing ".0".
func numStr(v any) string {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case string:
		return x
	}
	return fmt.Sprintf("%v", v)
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func arg(args []any, i int) any {
	if i < len(args) {
		return args[i]
	}
	return nil
}
