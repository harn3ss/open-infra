package cfn

import "testing"

// A condition may refer to other conditions ({"Condition": X} inside Fn::Or/And/Not) whatever their
// order, as on AWS. Evaluated in the map's (random) order, a referenced condition not yet evaluated read
// as false, so the same template included or skipped resources from one run to the next.
func TestConditions_ReferToEachOtherInAnyOrder(t *testing.T) {
	tmpl, err := Parse([]byte(`
Parameters:
  Env: { Type: String, Default: prod }
Conditions:
  A1: !Or [ !Condition Z9IsProd, !Condition Z8IsStaging ]
  B2: !And [ !Condition A1, !Not [ !Condition Z8IsStaging ] ]
  C3: !Not [ !Condition B2 ]
  Z8IsStaging: !Equals [ !Ref Env, staging ]
  Z9IsProd: !Equals [ !Ref Env, prod ]
Resources:
  OnlyInProd:
    Type: AWS::SNS::Topic
    Condition: B2
    Properties: { TopicName: !If [ A1, prod-topic, other-topic ] }
`))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ { // map order varies per range; one wrong evaluation fails the test
		r := newResolver(tmpl, map[string]any{"Env": "prod"}, nil, nil)
		r.evalConditions()
		if !r.conds["A1"] || !r.conds["B2"] || r.conds["C3"] {
			t.Fatalf("run %d: A1=%v B2=%v C3=%v, want true true false", i, r.conds["A1"], r.conds["B2"], r.conds["C3"])
		}
		if got := r.resolve(map[string]any{"Fn::If": []any{"A1", "prod-topic", "other-topic"}}); got != "prod-topic" {
			t.Fatalf("run %d: Fn::If A1 = %v", i, got)
		}
		if len(r.findings) != 0 {
			t.Fatalf("run %d: findings %v", i, r.findings)
		}
	}
}

// A condition that refers to itself, directly or through another, is a finding, never a hang.
func TestConditions_CycleIsAFinding(t *testing.T) {
	tmpl, err := Parse([]byte(`
Conditions:
  Ping: !Not [ !Condition Pong ]
  Pong: !Not [ !Condition Ping ]
Resources:
  T: { Type: AWS::SNS::Topic }
`))
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(tmpl, nil, nil, nil)
	r.evalConditions()
	if len(r.findings) == 0 {
		t.Fatal("a condition cycle must be reported")
	}
}
