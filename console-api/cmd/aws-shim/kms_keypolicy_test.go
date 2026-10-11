package main

import (
	"strings"
	"testing"
)

const testKeyID = "11111111-2222-4333-8444-555555555555"

// A faithful key policy with the default root statement + two principal statements translates to exactly
// two grants (the root statement is skipped), each scoped to Key::<id> with the right principals/actions.
func TestTranslateKeyPolicy_Faithful(t *testing.T) {
	doc := `{
      "Version": "2012-10-17",
      "Statement": [
        {"Sid":"Root","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"},
        {"Sid":"App","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/app"},"Action":["kms:Encrypt","kms:Decrypt"],"Resource":"*"},
        {"Sid":"Admin","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/kms-admin"},"Action":"kms:*","Resource":"*"}
      ]}`
	out, err := translateKeyPolicy(doc, testKeyID)
	if err != nil {
		t.Fatalf("faithful policy must translate: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 grants (root statement skipped), got %d: %#v", len(out), out)
	}
	// Grant 0: the user, encrypt+decrypt, on this key.
	g0 := out[0]
	if len(g0.appliesTo) != 1 || g0.appliesTo[0] != "User::app" {
		t.Errorf("grant 0 appliesTo should be [User::app], got %#v", g0.appliesTo)
	}
	s0 := g0.statements[0].(map[string]any)
	if s0["effect"] != "Allow" {
		t.Errorf("grant 0 effect: %#v", s0["effect"])
	}
	if acts, _ := s0["actions"].([]any); len(acts) != 2 || acts[0] != "kms:Encrypt" || acts[1] != "kms:Decrypt" {
		t.Errorf("grant 0 actions: %#v", s0["actions"])
	}
	if res, _ := s0["resources"].([]any); len(res) != 1 || res[0] != "Key::"+testKeyID {
		t.Errorf("grant 0 resources should be [Key::<id>], got %#v", s0["resources"])
	}
	// Grant 1: the role, kms:*.
	if len(out[1].appliesTo) != 1 || out[1].appliesTo[0] != "Role::kms-admin" {
		t.Errorf("grant 1 appliesTo should be [Role::kms-admin], got %#v", out[1].appliesTo)
	}
}

// A policy that is ONLY the default root statement yields no grants (fully delegated to identity policies).
func TestTranslateKeyPolicy_RootOnlySkipped(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}]}`
	out, err := translateKeyPolicy(doc, testKeyID)
	if err != nil {
		t.Fatalf("root-only policy must translate (to nothing): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("root-only policy must yield no grants, got %d", len(out))
	}
}

// A single Statement object (not an array), a bare "*" action, a "*" principal, and a Deny all translate.
func TestTranslateKeyPolicy_SingleObjectWildcardsDeny(t *testing.T) {
	doc := `{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"*","Resource":"*"}}`
	out, err := translateKeyPolicy(doc, testKeyID)
	if err != nil {
		t.Fatalf("single-object policy must translate: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 grant, got %d", len(out))
	}
	if out[0].appliesTo[0] != "*" {
		t.Errorf("'*' principal should map to appliesTo '*', got %#v", out[0].appliesTo)
	}
	s := out[0].statements[0].(map[string]any)
	if s["effect"] != "Deny" {
		t.Errorf("effect should be Deny, got %#v", s["effect"])
	}
	if acts, _ := s["actions"].([]any); len(acts) != 1 || acts[0] != "kms:*" {
		t.Errorf("bare '*' action should map to kms:*, got %#v", s["actions"])
	}
}

// A specific-key-ARN Resource naming THIS key is accepted; naming another key refuses.
func TestTranslateKeyPolicy_ResourceKeyARN(t *testing.T) {
	ok := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/app"},"Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:123456789012:key/` + testKeyID + `"}}`
	if _, err := translateKeyPolicy(ok, testKeyID); err != nil {
		t.Errorf("a Resource naming THIS key must be accepted: %v", err)
	}
	other := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/app"},"Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:123456789012:key/99999999-0000-0000-0000-000000000000"}}`
	if _, err := translateKeyPolicy(other, testKeyID); err == nil {
		t.Error("a Resource naming a DIFFERENT key must refuse")
	}
}

// FAIL-CLOSED: anything the data plane can't honor faithfully refuses the WHOLE policy.
func TestTranslateKeyPolicy_FailClosed(t *testing.T) {
	cases := map[string]struct {
		doc  string
		want string
	}{
		"condition": {
			`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:user/a"},"Action":"kms:*","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}}}}`,
			"Condition",
		},
		"non-kms action": {
			`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:user/a"},"Action":"s3:GetObject","Resource":"*"}}`,
			"not a kms",
		},
		"service principal": {
			`{"Statement":{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"kms:Decrypt","Resource":"*"}}`,
			"needs an AWS principal",
		},
		"bad effect": {
			`{"Statement":{"Effect":"Maybe","Principal":{"AWS":"arn:aws:iam::1:user/a"},"Action":"kms:*","Resource":"*"}}`,
			"Allow",
		},
		"foreign resource": {
			`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:user/a"},"Action":"kms:*","Resource":"arn:aws:s3:::bucket"}}`,
			"Resource",
		},
		"not json": {`}{not json`, "valid JSON"},
		"empty":    {``, "empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := translateKeyPolicy(c.doc, testKeyID); err == nil {
				t.Fatalf("expected a fail-closed refusal (want containing %q), got nil", c.want)
			} else if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal %q should contain %q", err.Error(), c.want)
			}
		})
	}
}

// The synthesized default key policy carries the account root with kms:* on *.
func TestDefaultKeyPolicyJSON(t *testing.T) {
	js := defaultKeyPolicyJSON("123456789012")
	for _, want := range []string{`"Effect":"Allow"`, `arn:aws:iam::123456789012:root`, `"Action":"kms:*"`, `"Resource":"*"`} {
		if !strings.Contains(js, want) {
			t.Errorf("default key policy missing %q: %s", want, js)
		}
	}
}
