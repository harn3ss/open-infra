package graphql

import "testing"

// @aws_subscribe(mutations:) on a Subscription field declares which mutations trigger it (AppSync's
// SDL-native equivalent of a subscription's triggeredBy) — parsed into Schema.SubscriptionTriggers.
func TestSchema_AwsSubscribeTriggers(t *testing.T) {
	s, err := ParseSchema(`
		type Todo { id: ID! name: String! }
		type Mutation { createTodo(name: String!): Todo updateTodo(id: ID!): Todo }
		type Subscription {
			onCreateTodo: Todo @aws_subscribe(mutations: ["createTodo"])
			onAnyChange: Todo @aws_subscribe(mutations: ["createTodo", "updateTodo"])
			onNothing: Todo
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	tr := s.SubscriptionTriggers() // mutation → subscription fields
	if !contains(tr["createTodo"], "onCreateTodo") || !contains(tr["createTodo"], "onAnyChange") {
		t.Errorf("createTodo triggers = %v, want onCreateTodo + onAnyChange", tr["createTodo"])
	}
	if !contains(tr["updateTodo"], "onAnyChange") || contains(tr["updateTodo"], "onCreateTodo") {
		t.Errorf("updateTodo triggers = %v, want only onAnyChange", tr["updateTodo"])
	}
	// A subscription field without @aws_subscribe contributes no triggers.
	for mut, subs := range tr {
		if contains(subs, "onNothing") {
			t.Errorf("onNothing should trigger nothing, but appears for %q", mut)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
