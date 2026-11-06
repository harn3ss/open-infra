package main

// EC2 key pairs keep each account's apart, against a real Postgres store (OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"golang.org/x/crypto/ssh"
)

// newSSHPublicKey is a fresh ED25519 public key in OpenSSH form.
func newSSHPublicKey(t *testing.T) string {
	t.Helper()
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

var keyPairIDRe = regexp.MustCompile(`<keyPairId>(key-[0-9a-f]+)</keyPairId>`)

// A store made before accounts migrates in place (its key pairs are the management account's, the primary
// key becomes (account, name)); then each account has key pairs of its own, of the same name or with a ":"
// in it, never seen, replaced or deleted by another account.
func TestServicesPG_EC2KeyPairsAccounts(t *testing.T) {
	ctx := context.Background()
	db := freshPGDB(t)
	if _, err := db.Exec(`CREATE TABLE ec2_key_pairs (
    name        text PRIMARY KEY,
    key_pair_id text NOT NULL UNIQUE,
    key_type    text NOT NULL,
    fingerprint text NOT NULL,
    public_key  text NOT NULL,
    tags        jsonb NOT NULL DEFAULT '{}',
    created     timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	oldPub := newSSHPublicKey(t)
	if _, err := db.Exec(`INSERT INTO ec2_key_pairs (name, key_pair_id, key_type, fingerprint, public_key) VALUES ('ops','key-00000000000000001','ed25519','fp',$1)`, oldPub); err != nil {
		t.Fatal(err)
	}
	st := &ec2KeyStore{db: db}
	for i := 0; i < 2; i++ { // idempotent
		if err := st.ensureSchema(ctx); err != nil {
			t.Fatalf("ensureSchema (run %d): %v", i+1, err)
		}
	}
	var pk string
	if err := db.QueryRow(`SELECT string_agg(a.attname, ',' ORDER BY array_position(i.indkey, a.attnum)) FROM pg_index i
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) WHERE i.indrelid = 'ec2_key_pairs'::regclass AND i.indisprimary`).Scan(&pk); err != nil || pk != "account,name" {
		t.Fatalf("the primary key is (%s), %v; want (account,name)", pk, err)
	}
	var acct string
	if err := db.QueryRow(`SELECT account FROM ec2_key_pairs WHERE key_pair_id='key-00000000000000001'`).Scan(&acct); err != nil || acct != "" {
		t.Fatalf("a key pair made before accounts is the management account's: %q %v", acct, err)
	}

	h, _ := ec2Fixture(t)
	h.keys = st
	h.door.authz = doorAccountsAuthz(t)
	member, mgmt := memberCtx(), context.Background()
	imp := func(c context.Context, claims iam.Claims, name, pub string) *httptest.ResponseRecorder {
		return ec2CallIn(h, c, claims, url.Values{"Action": {"ImportKeyPair"}, "KeyName": {name},
			"PublicKeyMaterial": {base64.StdEncoding.EncodeToString([]byte(pub))}})
	}
	describe := func(c context.Context, claims iam.Claims, extra url.Values) string {
		form := url.Values{"Action": {"DescribeKeyPairs"}, "IncludePublicKey": {"true"}}
		for k, v := range extra {
			form[k] = v
		}
		return ec2CallIn(h, c, claims, form).Body.String()
	}

	// The member account has none of the management account's key pairs.
	if body := describe(member, ec2Bob, nil); strings.Contains(body, "key-00000000000000001") || strings.Contains(body, "<keyName>") {
		t.Errorf("a member account listed the management account's key pairs: %s", body)
	}
	if body := describe(member, ec2Bob, url.Values{"KeyName.1": {"ops"}}); !strings.Contains(body, "InvalidKeyPair.NotFound") {
		t.Errorf("the management account's key pair is not the member account's: %s", body)
	}
	// The same name, and a name with ":", in the member account: its own.
	memberPub, memberColonPub, mgmtColonPub := newSSHPublicKey(t), newSSHPublicKey(t), newSSHPublicKey(t)
	w := imp(member, ec2Bob, "ops", memberPub)
	if w.Code != 200 {
		t.Fatalf("member ImportKeyPair ops: %d %s", w.Code, w.Body.String())
	}
	memberOpsID := keyPairIDRe.FindStringSubmatch(w.Body.String())[1]
	if w = imp(member, ec2Bob, testMember+":ops", memberColonPub); w.Code != 200 {
		t.Fatalf("member ImportKeyPair with a ':' (and a member-key shape) in its name: %d %s", w.Code, w.Body.String())
	}
	if w = imp(mgmt, ec2Alice, testMember+":ops", mgmtColonPub); w.Code != 200 {
		t.Fatalf("the management account's key pair of that same name is its own: %d %s", w.Code, w.Body.String())
	}
	if w = imp(member, ec2Bob, "ops", memberPub); !strings.Contains(w.Body.String(), "InvalidKeyPair.Duplicate") {
		t.Errorf("a name is unique within its account: %s", w.Body.String())
	}

	body := describe(member, ec2Bob, nil)
	mustHave(t, "the member account's key pairs", body, []string{memberOpsID, memberPub, memberColonPub}, []string{"key-00000000000000001", oldPub, mgmtColonPub})
	body = describe(mgmt, ec2Alice, nil)
	mustHave(t, "the management account's key pairs", body, []string{"key-00000000000000001", oldPub, mgmtColonPub}, []string{memberOpsID, memberPub, memberColonPub})

	// CloudFormation's key pairs are the stack's account's.
	if keys, err := st.publicKeys(member); err != nil || keys["ops"] != memberPub || keys[testMember+":ops"] != memberColonPub || len(keys) != 2 {
		t.Errorf("the member account's key pairs for its stacks: %v %v", keys, err)
	}
	if keys, err := st.publicKeys(mgmt); err != nil || keys["ops"] != oldPub || keys[testMember+":ops"] != mgmtColonPub || len(keys) != 2 {
		t.Errorf("the management account's key pairs for its stacks: %v %v", keys, err)
	}

	// Deleting by the management account's id or name, as the member account, deletes the member's own
	// alone (AWS: deleting one that does not exist succeeds).
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DeleteKeyPair"}, "KeyPairId": {"key-00000000000000001"}}); w.Code != 200 || strings.Contains(w.Body.String(), "<keyPairId>") {
		t.Errorf("member DeleteKeyPair by the management account's id: %d %s", w.Code, w.Body.String())
	}
	if w = ec2CallIn(h, member, ec2Bob, url.Values{"Action": {"DeleteKeyPair"}, "KeyName": {"ops"}}); w.Code != 200 || !strings.Contains(w.Body.String(), memberOpsID) {
		t.Errorf("member DeleteKeyPair ops: %d %s", w.Code, w.Body.String())
	}
	if body = describe(mgmt, ec2Alice, url.Values{"KeyName.1": {"ops"}}); !strings.Contains(body, "key-00000000000000001") {
		t.Errorf("the management account's ops must be untouched: %s", body)
	}
	if body = describe(member, ec2Bob, url.Values{"KeyName.1": {"ops"}}); !strings.Contains(body, "InvalidKeyPair.NotFound") {
		t.Errorf("the member account's ops is gone: %s", body)
	}
}
