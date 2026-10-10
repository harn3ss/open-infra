package vtl

import (
	"fmt"
	"strconv"
)

// Value coercions the AppSync $util dispatcher (util.go) depends on. These mirror the identical,
// stable helpers in the shared Velocity core (github.com/harn3ss/open-infra/vtl): the engine keeps
// its own unexported copies for rendering, and this package keeps its own for the concrete $util —
// the two never drift because the semantics (how a VTL value stringifies / numifies / is truthy) are
// fixed Velocity behaviour, not AppSync-specific. They stay here so util.go is self-contained in its
// own module after the engine was extracted.

func toStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return numStr(x)
	case map[string]any, []any:
		return jsonString(x)
	}
	return fmt.Sprintf("%v", v)
}

func truthy(v any) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return true // Velocity: any non-null, non-false reference is true
}

func toNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}
