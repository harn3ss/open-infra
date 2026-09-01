package dynamodb

import (
	"reflect"
	"testing"
)

func TestToDynamoDB_Shapes(t *testing.T) {
	cases := []struct {
		in   any
		want map[string]any
	}{
		{"hi", map[string]any{"S": "hi"}},
		{float64(3), map[string]any{"N": "3"}},
		{float64(3.5), map[string]any{"N": "3.5"}},
		{true, map[string]any{"BOOL": true}},
		{nil, map[string]any{"NULL": true}},
		{[]any{"a", float64(1)}, map[string]any{"L": []any{map[string]any{"S": "a"}, map[string]any{"N": "1"}}}},
		{map[string]any{"k": "v"}, map[string]any{"M": map[string]any{"k": map[string]any{"S": "v"}}}},
	}
	for _, c := range cases {
		if got := ToDynamoDB(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ToDynamoDB(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ToDynamoDB and fromDynamoDB are inverses over the value shapes an item carries — the property the
// aws-shim relies on to store a wire Item and read it back byte-faithfully.
func TestToDynamoDB_RoundTripsWithFromDynamoDB(t *testing.T) {
	item := map[string]any{
		"id":    "u1",
		"name":  "Ada",
		"age":   float64(36),
		"admin": true,
		"tags":  []any{"x", "y"},
		"meta":  map[string]any{"tier": "b", "score": float64(9)},
	}
	typed := ToItem(item)
	// fromDynamoDB un-marshals a typed value back to plain; applied per attribute it must reproduce
	// the original item.
	back := map[string]any{}
	for k, v := range typed {
		back[k] = fromDynamoDB(v)
	}
	if !reflect.DeepEqual(back, item) {
		t.Fatalf("round-trip lost fidelity:\n got %#v\nwant %#v", back, item)
	}
}
