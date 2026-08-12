// Self-contained (stdlib only) chaos chain grammar tool.
//
//	go run ./tools/chainforge validate           # every scenario chain is type-legal (CI gate)
//	go run ./tools/chainforge generate -seed 7 -count 5
//	go run ./tools/chainforge matrix             # full compatibility matrix (audit lens)
//
// The grammar (chaos/grammar.json) is the fail-closed source of truth: an edge that
// no connector blesses is illegal, so generated chains are type-legal by construction
// and hand-authored scenarios can never quietly drift off the grammar.
module openinfra/tools/chainforge

go 1.24
