package render

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const emailsenderCompositionPath = "../../platform/abstraction/emailsender-composition.yaml"

const (
	esUID    = "00000000-0000-0000-0000-0000000e5e01"
	esMember = "912345678901"
)

// esCtx is the observed composite (claim notify in namespace shop) plus the extra resources Crossplane
// fetched (nil: none yet) and the composed resources it observed (nil: none).
func esCtx(spec map[string]any, extra map[string]any, observed map[string]any) map[string]any {
	ctx := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"apiVersion": "openinfra.dev/v1",
			"kind":       "XEmailSender",
			"spec":       spec,
			"metadata": map[string]any{
				"name": "notify-x7k2p",
				"uid":  esUID,
				"labels": map[string]any{
					"crossplane.io/claim-name":      "notify",
					"crossplane.io/claim-namespace": "shop",
				},
			},
		}}},
		"context": map[string]any{"apiextensions.crossplane.io/environment": map[string]any{
			"awsAccountId": "000000000000", "awsRegion": "eu-west-1"}},
	}
	if extra != nil {
		ctx["extraResources"] = extra
	}
	if observed != nil {
		ctx["observed"].(map[string]any)["resources"] = observed
	}
	return ctx
}

// esNamespace is the claim namespace as Crossplane fetches it, labelled into acct ("" = no account label).
func esNamespace(acct string) map[string]any {
	md := map[string]any{"name": "shop"}
	if acct != "" {
		md["labels"] = map[string]any{"openinfra.dev/account-id": acct}
	}
	return map[string]any{"claim-namespace": map[string]any{"items": []any{map[string]any{"resource": map[string]any{"metadata": md}}}}}
}

// esWithAccount adds the member account's kind: Account (its home first) with these verified identities.
func esWithAccount(extra map[string]any, verified ...any) map[string]any {
	spec := map[string]any{"accountId": esMember, "namespaces": []any{"team-a", "shop"}}
	if len(verified) > 0 {
		spec["ses"] = map[string]any{"verifiedIdentities": verified}
	}
	extra["account"] = map[string]any{"items": []any{map[string]any{"resource": map[string]any{"spec": spec}}}}
	return extra
}

func esSpec() map[string]any {
	return map[string]any{"fromAddress": "noreply@example.com", "fromName": "Acme Notifications"}
}

func esDocs(t *testing.T, out string) []map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatalf("rendered output is not YAML: %v\n%s", err, out)
	}
	return docs
}

// esManifest is the manifest of the composed Object named res ("" when it is not rendered).
func esManifest(docs []map[string]any, res string) map[string]any {
	for _, d := range docs {
		if mstr(d, "metadata", "annotations", "gotemplating.fn.crossplane.io/composition-resource-name") == res {
			m, _ := mget(d, "spec", "forProvider", "manifest").(map[string]any)
			return m
		}
	}
	return nil
}

func esStatus(docs []map[string]any) map[string]any {
	for _, d := range docs {
		if d["kind"] == "XEmailSender" {
			s, _ := d["status"].(map[string]any)
			return s
		}
	}
	return nil
}

func esJobRes(docs []map[string]any) string {
	for _, d := range docs {
		if r := mstr(d, "metadata", "annotations", "gotemplating.fn.crossplane.io/composition-resource-name"); strings.HasPrefix(r, "smtp-credentials-") {
			return r
		}
	}
	return ""
}

// The expected access key id and its key-store Secret name, as the key store (awskeys.SecretName) names it.
func esKey() (ak, secret string) {
	sum := sha256.Sum256([]byte("emailsender-key|" + esUID))
	ak = "OIAK" + strings.ToUpper(hex.EncodeToString(sum[:])[:16])
	s := sha256.Sum256([]byte(ak))
	return ak, "iam-ak-" + hex.EncodeToString(s[:])[:40]
}

// Until Crossplane has fetched the claim's namespace (its account), nothing is made: no user, no key, no
// secret — a user is never made in the wrong account.
func TestEmailSender_WaitsForItsAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	for name, extra := range map[string]map[string]any{
		"namespace not fetched":      nil,
		"member account not fetched": esNamespace(esMember),
	} {
		out := render(t, tmpl, esCtx(esSpec(), extra, nil))
		docs := esDocs(t, out)
		for _, res := range []string{"smtp-user", "smtp-secret"} {
			if esManifest(docs, res) != nil {
				t.Errorf("%s: %s was rendered before the account was known", name, res)
			}
		}
		if esJobRes(docs) != "" {
			t.Errorf("%s: the credential Job was rendered before the account was known", name)
		}
		if st := esStatus(docs); st["ready"] != "false" {
			t.Errorf("%s: status %v, want not ready", name, st)
		}
		if !strings.Contains(out, "kind: ExtraResources") || !strings.Contains(out, `matchName: "shop"`) {
			t.Errorf("%s: the claim's namespace must be requested:\n%s", name, out)
		}
	}
	out := render(t, tmpl, esCtx(esSpec(), esNamespace(esMember), nil))
	if !strings.Contains(out, "kind: Account") || !strings.Contains(out, `matchName: "`+esMember+`"`) {
		t.Errorf("a member account's Account must be requested:\n%s", out)
	}
	out = render(t, tmpl, esCtx(esSpec(), esNamespace(""), nil))
	if strings.Contains(out, "kind: Account") {
		t.Errorf("the management account's claim needs no Account:\n%s", out)
	}
}

// In the management account: an IAM user in the console's IAM home whose only permission is
// ses:SendRawEmail as the From address, decided by IAM policy alone, and a Job that mints its access key.
func TestEmailSender_ManagementAccountUserAndKey(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	docs := esDocs(t, render(t, tmpl, esCtx(esSpec(), esNamespace(""), nil)))
	u := esManifest(docs, "smtp-user")
	if u == nil || mstr(u, "kind") != "User" || mstr(u, "apiVersion") != "iam.openinfra.dev/v1" {
		t.Fatalf("want a kind: User, got %v", u)
	}
	user := mstr(u, "metadata", "name")
	if !regexp.MustCompile(`^ses-smtp-user-[0-9a-f]{12}$`).MatchString(user) || mstr(u, "metadata", "namespace") != "open-infra-console" {
		t.Fatalf("the SMTP user must be ses-smtp-user-<id> in the management account's IAM home, got %s/%s", mstr(u, "metadata", "namespace"), user)
	}
	if mstr(u, "metadata", "labels", "openinfra.dev/iam-authz") != "enforce" {
		t.Error("the SMTP user must be decided by IAM policy alone (the canary label)")
	}
	if g, _ := mget(u, "spec", "groups").([]any); len(g) != 0 || mget(u, "spec", "policies") != nil {
		t.Errorf("the SMTP user has no groups and no attached policies: %v", u["spec"])
	}
	inl, _ := mget(u, "spec", "inlinePolicies").([]any)
	if len(inl) != 1 || mstr(inl[0], "name") != "AmazonSesSendingAccess" {
		t.Fatalf("want one inline policy AmazonSesSendingAccess, got %v", inl)
	}
	stmts, _ := mget(inl[0], "document", "Statement").([]any)
	if len(stmts) != 1 || mstr(stmts[0], "Effect") != "Allow" || mstr(stmts[0], "Action") != "ses:SendRawEmail" ||
		mstr(stmts[0], "Resource") != "arn:aws:ses:*:*:identity/noreply@example.com" || mget(stmts[0], "Condition") != nil {
		t.Fatalf("the policy must allow ses:SendRawEmail on the From address's identity only, got %v", stmts)
	}

	ak, keySecret := esKey()
	jobRes := esJobRes(docs)
	job := esManifest(docs, jobRes)
	if job == nil || mstr(job, "kind") != "Job" || mstr(job, "metadata", "namespace") != "open-infra-aws-shim" {
		t.Fatalf("want the credential Job in the aws-shim's namespace, got %v", job)
	}
	pod, _ := mget(job, "spec", "template", "spec").(map[string]any)
	if mstr(pod, "serviceAccountName") != "openinfra-emailsender-setup" {
		t.Errorf("the Job runs as openinfra-emailsender-setup, got %q", mstr(pod, "serviceAccountName"))
	}
	ctrs, _ := pod["containers"].([]any)
	if len(ctrs) != 1 || !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(mstr(ctrs[0], "image")) {
		t.Fatalf("the Job's image must be pinned by digest: %v", ctrs)
	}
	if mget(job, "spec", "ttlSecondsAfterFinished") != nil {
		t.Error("a provider-managed Job must not carry a TTL (the provider would re-create it every poll)")
	}
	env := map[string]string{}
	for _, e := range mget(ctrs[0], "env").([]any) {
		env[mstr(e, "name")] = mstr(e, "value")
	}
	if env["ACCESS_KEY_ID"] != ak || env["KEY_SECRET"] != keySecret || env["OWNER"] != user || env["ACCOUNT"] != "" ||
		env["REGION"] != "eu-west-1" || env["XR_UID"] != esUID || env["XR_KIND"] != "XEmailSender" || env["XR_NAME"] != "notify-x7k2p" {
		t.Errorf("Job env %v (want key %s in %s for %s, the management account, eu-west-1, owned by the composite)", env, ak, keySecret, user)
	}
	if esManifest(docs, "smtp-secret") != nil {
		t.Error("the connection secret is rendered only once the key is minted")
	}
	st := esStatus(docs)
	if st["verificationStatus"] != "SUCCESS" || st["smtpUsername"] != ak || st["iamUser"] != user ||
		st["iamUserArn"] != "arn:aws:iam::000000000000:user/"+user || st["ready"] != "false" {
		t.Errorf("status %v", st)
	}
}

// Once the Job has minted the key, the claim's <name>-smtp secret points apps at the SES SMTP interface
// with these credentials; the password is copied from the key-store Secret, never written here.
func TestEmailSender_ConnectionSecret(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	first := esDocs(t, render(t, tmpl, esCtx(esSpec(), esNamespace(""), nil)))
	observed := map[string]any{esJobRes(first): map[string]any{"resource": map[string]any{"status": map[string]any{
		"atProvider": map[string]any{"manifest": map[string]any{"status": map[string]any{"succeeded": float64(1)}}}}}}}
	out := render(t, tmpl, esCtx(esSpec(), esNamespace(""), observed))
	docs := esDocs(t, out)
	s := esManifest(docs, "smtp-secret")
	if s == nil {
		t.Fatalf("no connection secret after the key was minted:\n%s", out)
	}
	ak, keySecret := esKey()
	if mstr(s, "metadata", "name") != "notify-smtp" || mstr(s, "metadata", "namespace") != "shop" {
		t.Errorf("want shop/notify-smtp, got %s/%s", mstr(s, "metadata", "namespace"), mstr(s, "metadata", "name"))
	}
	for k, want := range map[string]string{"SMTP_HOST": "aws-shim.open-infra-aws-shim.svc.cluster.local", "SMTP_PORT": "587",
		"SMTP_USERNAME": ak, "SMTP_FROM": "noreply@example.com", "SMTP_FROM_NAME": "Acme Notifications"} {
		if got := mstr(s, "stringData", k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if mget(s, "stringData", "SMTP_PASSWORD") != nil || strings.Contains(out, "smtpPassword:") {
		t.Error("the password must never be written by the composition")
	}
	var ref map[string]any
	for _, d := range docs {
		if mstr(d, "metadata", "annotations", "gotemplating.fn.crossplane.io/composition-resource-name") == "smtp-secret" {
			refs, _ := mget(d, "spec", "references").([]any)
			if len(refs) == 1 {
				ref, _ = refs[0].(map[string]any)
			}
		}
	}
	if mstr(ref, "patchesFrom", "name") != keySecret || mstr(ref, "patchesFrom", "namespace") != "open-infra-aws-shim" ||
		mstr(ref, "patchesFrom", "fieldPath") != "data.smtpPassword" || mstr(ref, "toFieldPath") != "data.SMTP_PASSWORD" {
		t.Errorf("SMTP_PASSWORD must be copied from the key-store Secret's smtpPassword, got %v", ref)
	}
	if st := esStatus(docs); st["ready"] != "true" || st["connectionSecret"] != "notify-smtp" {
		t.Errorf("status %v, want ready with the connection secret", st)
	}
}

// In a member account the user lives in the account's IAM home, the key records the account, and the From
// address is verified only if the account's Account lists it or its domain.
func TestEmailSender_MemberAccount(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	for _, tc := range []struct {
		name     string
		verified []any
		want     string
	}{
		{"domain verified", []any{"Example.com"}, "SUCCESS"},
		{"address verified", []any{"noreply@example.com"}, "SUCCESS"},
		{"another address verified", []any{"billing@example.com"}, "PENDING"},
		{"nothing verified", nil, "PENDING"},
	} {
		docs := esDocs(t, render(t, tmpl, esCtx(esSpec(), esWithAccount(esNamespace(esMember), tc.verified...), nil)))
		u := esManifest(docs, "smtp-user")
		if u == nil || mstr(u, "metadata", "namespace") != "team-a" {
			t.Fatalf("%s: the SMTP user must be in the member account's IAM home (team-a), got %v", tc.name, u)
		}
		job := esManifest(docs, esJobRes(docs))
		env := map[string]string{}
		for _, e := range mget(job, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)["env"].([]any) {
			env[mstr(e, "name")] = mstr(e, "value")
		}
		if env["ACCOUNT"] != esMember {
			t.Errorf("%s: the key must record the member account, got %q", tc.name, env["ACCOUNT"])
		}
		st := esStatus(docs)
		if st["verificationStatus"] != tc.want || st["iamUserArn"] != "arn:aws:iam::"+esMember+":user/"+mstr(u, "metadata", "name") {
			t.Errorf("%s: status %v, want %s", tc.name, st, tc.want)
		}
	}
}

// The From address is the policy's resource, so a wildcard (or anything that is not one address) is
// refused rather than becoming a grant on many identities.
func TestEmailSender_FromAddressIsNeverAWildcard(t *testing.T) {
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	for _, from := range []string{"*@example.com", "noreply@*.com", "a?b@example.com", "noreply@example", "a b@example.com", `x"@example.com`} {
		if err := renderErr(tmpl, esCtx(map[string]any{"fromAddress": from}, esNamespace(""), nil)); err == nil {
			t.Errorf("fromAddress %q rendered", from)
		}
	}
	xrd := mustRead(t, "../../platform/abstraction/emailsender-xrd.yaml")
	m := regexp.MustCompile(`pattern: '([^']+)'`).FindStringSubmatch(xrd)
	if m == nil {
		t.Fatal("the XRD's fromAddress has no pattern")
	}
	re := regexp.MustCompile(m[1])
	for _, from := range []string{"*@example.com", "noreply@*.com", "a?b@example.com"} {
		if re.MatchString(from) {
			t.Errorf("the XRD admits the wildcard address %q", from)
		}
	}
	if !re.MatchString("no-reply+tag@mail.example.com") {
		t.Error("the XRD refuses an ordinary address")
	}
}

// esSMTPPassword is AWS's version-4 SES SMTP password derivation (the aws-shim's sesSMTPPassword is
// checked against AWS's own published script; this repeats it for the Job's output).
func esSMTPPassword(secret, region string) string {
	sign := func(key []byte, msg string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	sig := sign([]byte("AWS4"+secret), "11111111")
	for _, p := range []string{region, "ses", "aws4_request", "SendRawEmail"} {
		sig = sign(sig, p)
	}
	return base64.StdEncoding.EncodeToString(append([]byte{0x04}, sig...))
}

const esStubKubectl = `#!/bin/sh
echo "kubectl $*" >> "$STUB/calls.log"
case "$*" in
  "create -f "*)
    if [ -f "$STUB/exists" ]; then echo "Error from server (AlreadyExists): secrets \"x\" already exists" >&2; exit 1; fi
    cp "$3" "$STUB/created.json" ;;
  *) echo "unexpected kubectl $*" >&2; exit 99 ;;
esac
`

// The rendered Job mints the key with AWS's derivation: run it (python3 and a stub kubectl) and check the
// Secret it creates — the access key, a fresh secret, the SMTP password of that secret in the install's
// region, the owner and account, the key store's labels, and the composite as its owner. A second run
// finds the Secret and changes nothing.
func TestEmailSender_JobMintsAWSDerivedCredentials(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	tmpl := extractInlineTemplate(t, emailsenderCompositionPath)
	out := render(t, tmpl, esCtx(esSpec(), esWithAccount(esNamespace(esMember), "example.com"), nil))
	docs := esDocs(t, out)
	job := esManifest(docs, esJobRes(docs))
	ctr := mget(job, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)
	var env []string
	for _, e := range ctr["env"].([]any) {
		env = append(env, mstr(e, "name")+"="+mstr(e, "value"))
	}
	script := setupScript(t, out, "name: mint")
	root := t.TempDir()
	stub, bin, tmp := filepath.Join(root, "stub"), filepath.Join(root, "bin"), filepath.Join(root, "tmp")
	for _, d := range []string{stub, bin, tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(bin, "kubectl"), esStubKubectl)
	if err := os.Chmod(filepath.Join(bin, "kubectl"), 0o755); err != nil {
		t.Fatal(err)
	}
	script = strings.ReplaceAll(script, "/tmp/key.json", filepath.Join(tmp, "key.json"))
	py, _ := exec.LookPath("python3")
	path := bin + string(os.PathListSeparator) + filepath.Dir(py) + string(os.PathListSeparator) + "/usr/bin:/bin"
	for _, sh := range posixShells(t) {
		_ = os.Remove(filepath.Join(stub, "exists"))
		cmd := exec.Command(sh[0], append(sh[1:], "-c", script)...)
		cmd.Env = append([]string{"PATH=" + path, "STUB=" + stub, "HOME=" + tmp}, env...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: the Job failed: %v\n%s", shellName(sh), err, b)
		}
		raw, err := os.ReadFile(filepath.Join(stub, "created.json"))
		if err != nil {
			t.Fatalf("%s: the Job created no Secret: %v", shellName(sh), err)
		}
		var sec struct {
			Metadata struct {
				Name, Namespace string
				Labels          map[string]string
				OwnerReferences []map[string]any
			}
			StringData map[string]string
		}
		if err := json.Unmarshal(raw, &sec); err != nil {
			t.Fatalf("%s: %v\n%s", shellName(sh), err, raw)
		}
		ak, keySecret := esKey()
		d := sec.StringData
		if sec.Metadata.Name != keySecret || sec.Metadata.Namespace != "open-infra-aws-shim" || d["accessKeyId"] != ak ||
			!strings.HasPrefix(d["owner"], "ses-smtp-user-") || d["account"] != esMember {
			t.Errorf("%s: Secret %s/%s %v", shellName(sh), sec.Metadata.Namespace, sec.Metadata.Name, d)
		}
		if raw, err := base64.StdEncoding.DecodeString(d["secretKey"]); err != nil || len(raw) != 30 {
			t.Errorf("%s: the secret key must be 30 random bytes, base64 (40 characters), got %q", shellName(sh), d["secretKey"])
		}
		if want := esSMTPPassword(d["secretKey"], "eu-west-1"); d["smtpPassword"] != want {
			t.Errorf("%s: smtpPassword %q, want AWS's derivation of the secret in eu-west-1 (%q)", shellName(sh), d["smtpPassword"], want)
		}
		if sec.Metadata.Labels["app.kubernetes.io/managed-by"] != "open-infra-console" || sec.Metadata.Labels["openinfra.dev/iam-user"] != d["owner"] {
			t.Errorf("%s: the key must carry the key store's labels, got %v", shellName(sh), sec.Metadata.Labels)
		}
		if len(sec.Metadata.OwnerReferences) != 1 || sec.Metadata.OwnerReferences[0]["uid"] != esUID ||
			sec.Metadata.OwnerReferences[0]["kind"] != "XEmailSender" || sec.Metadata.OwnerReferences[0]["blockOwnerDeletion"] != nil {
			t.Errorf("%s: the key must be owned by the composite (and block nothing), got %v", shellName(sh), sec.Metadata.OwnerReferences)
		}
		if _, err := os.Stat(filepath.Join(tmp, "key.json")); err == nil {
			t.Errorf("%s: the Job left the key on disk", shellName(sh))
		}
		// A rerun finds the Secret and succeeds without minting another.
		writeFile(t, filepath.Join(stub, "exists"), "")
		_ = os.Remove(filepath.Join(stub, "created.json"))
		cmd = exec.Command(sh[0], append(sh[1:], "-c", script)...)
		cmd.Env = append([]string{"PATH=" + path, "STUB=" + stub, "HOME=" + tmp}, env...)
		if b, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(b), "already exist") {
			t.Errorf("%s: a rerun must succeed on AlreadyExists: %v\n%s", shellName(sh), err, b)
		}
	}
}
