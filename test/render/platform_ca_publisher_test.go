package render

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The platform-ca-publisher (platform/aws-shim/platform-ca-publisher.yaml) publishes the root CA guests
// trust and keeps every platform certificate signed by it. These run its exact script against a stub
// kubectl that serves cert-manager objects from fixtures and records what the script writes.

const publisherPath = "../../platform/aws-shim/platform-ca-publisher.yaml"

const stubKubectlPublisher = `#!/bin/sh
echo "kubectl $*" >> "$STUB/calls.log"
ns=""
if [ "$1" = "-n" ]; then ns=$2; shift 2; fi
serve() { if [ -f "$STUB/$1" ]; then cat "$STUB/$1"; else echo '{"items":[]}'; fi; }
optional() { if [ -f "$STUB/$1" ]; then cat "$STUB/$1"; fi; }
case "$*" in
  "get certificate openinfra-root-ca -o json") cat "$STUB/root-cert.json" ;;
  "get clusterissuer openinfra-ca -o jsonpath={.spec.ca.secretName}") jq -j '.spec.ca.secretName' "$STUB/issuer.json" ;;
  "get certificate openinfra-aws-endpoints-ca -o json --ignore-not-found") optional aws-cert.json ;;
  "get clusterissuer openinfra-aws-endpoints -o jsonpath={.spec.ca.secretName}") jq -j '.spec.ca.secretName' "$STUB/aws-issuer.json" ;;
  "get environmentconfig openinfra-platform-ca -o json --ignore-not-found") optional envcfg.json ;;
  "get certificaterequests -o json") serve "crs-$ns.json" ;;
  "get certificates -o json") serve "certs-$ns.json" ;;
  "apply --server-side --field-manager=platform-ca-publisher -f -") cat > "$STUB/applied.json" ;;
  "patch certificate "*) printf '%s/%s %s\n' "$ns" "$3" "$7" >> "$STUB/patches.txt" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

func pemOf(body string) string {
	return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
}

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

const rootUID = "c747e019-0000-4555-88aa-10be45f721c6"

// certReq is a CertificateRequest for Certificate <cert> at <rev>; owner "" = not owned by the root.
func certReq(name, cert, rev, owner, issuer, certPEM, caPEM string, ready bool) map[string]any {
	st := "True"
	if !ready {
		st = "False"
	}
	md := map[string]any{"name": name, "creationTimestamp": "2026-01-01T00:00:00Z", "annotations": map[string]any{
		"cert-manager.io/certificate-name": cert, "cert-manager.io/certificate-revision": rev}}
	if owner != "" {
		md["ownerReferences"] = []any{map[string]any{"kind": "Certificate", "name": cert, "uid": owner}}
	}
	return map[string]any{"metadata": md,
		"spec": map[string]any{"issuerRef": map[string]any{"name": issuer, "kind": "ClusterIssuer", "group": "cert-manager.io"}},
		"status": map[string]any{"certificate": b64s(certPEM), "ca": b64s(caPEM), "conditions": []any{
			map[string]any{"type": "Approved", "status": "True"}, map[string]any{"type": "Ready", "status": st}}}}
}

func rootCert(rev int, secret string) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": "openinfra-root-ca", "uid": rootUID},
		"spec":   map[string]any{"secretName": secret, "issuerRef": map[string]any{"name": "openinfra-issuer", "kind": "ClusterIssuer", "group": "cert-manager.io"}},
		"status": map[string]any{"revision": rev, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}
}

func leafCert(name string, issuing bool) map[string]any {
	conds := []any{map[string]any{"type": "Ready", "status": "True"}}
	if issuing {
		conds = append(conds, map[string]any{"type": "Issuing", "status": "True"})
	}
	return map[string]any{"metadata": map[string]any{"name": name, "resourceVersion": "42", "generation": 3},
		"spec":   map[string]any{"issuerRef": map[string]any{"name": "openinfra-ca", "kind": "ClusterIssuer"}},
		"status": map[string]any{"conditions": conds}}
}

func runPublisher(t *testing.T, sh []string, fixtures map[string]any) (dir, out string, err error) {
	t.Helper()
	root := t.TempDir()
	dir, bin, tmp := filepath.Join(root, "stub"), filepath.Join(root, "bin"), filepath.Join(root, "tmp")
	for _, d := range []string{dir, bin, tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(stubKubectlPublisher), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range fixtures {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcilerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh[0], append(sh[1:], "-ceu", extractArgsScript(t, publisherPath))...)
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "STUB=" + dir, "HOME=" + tmp, "TMPDIR=" + tmp,
		"ROOT_NS=cert-manager", "ROOT_CERT=openinfra-root-ca", "ISSUER=openinfra-ca",
		"AWS_CA_CERT=openinfra-aws-endpoints-ca", "AWS_CA_ISSUER=openinfra-aws-endpoints",
		"PLATFORM_NAMESPACES=open-infra-aws-shim open-infra-ecr", "RENEW_BACKOFF_SECONDS=1800"}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	return dir, buf.String(), err
}

func readStub(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return string(b)
}

var (
	oldRoot = pemOf("T0xEUk9PVA==")
	newRoot = pemOf("TkVXUk9PVA==")
)

// The root published is the root Certificate's own current certificate (its CertificateRequest for the
// current revision, owned by it, approved and ready), never another revision's, a look-alike request's,
// or a leaf's view of it. Platform leaves still signed by another root are renewed (an Issuing
// condition, guarded by their resourceVersion); current leaves, and leaves already re-issuing, are not.
func TestPlatformCAPublisher_PublishesTheRootAndRenewsStaleLeaves(t *testing.T) {
	needJQ(t)
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh), func(t *testing.T) {
			dir, out, err := runPublisher(t, sh, map[string]any{
				"root-cert.json": rootCert(3, "openinfra-root-ca-2"),
				"issuer.json":    map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-root-ca-2"}}},
				"crs-cert-manager.json": items(
					certReq("openinfra-root-ca-2", "openinfra-root-ca", "2", rootUID, "openinfra-issuer", oldRoot, oldRoot, true),
					certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, newRoot, true),
					certReq("look-alike", "openinfra-root-ca", "3", "", "openinfra-issuer", pemOf("RVZJTA=="), "", true), // not owned
				),
				"certs-open-infra-aws-shim.json": items(leafCert("openinfra-ca-bundle", false), leafCert("aws-shim-internal-tls", false),
					leafCert("aws-shim-s3-site-ca-tls", true)),
				"crs-open-infra-aws-shim.json": items(
					certReq("openinfra-ca-bundle-1", "openinfra-ca-bundle", "1", "x", "openinfra-ca", "leaf", oldRoot, true),
					certReq("openinfra-ca-bundle-2", "openinfra-ca-bundle", "2", "x", "openinfra-ca", "leaf", newRoot, false), // in flight
					certReq("aws-shim-internal-tls-4", "aws-shim-internal-tls", "4", "x", "openinfra-ca", "leaf", newRoot, true),
					certReq("aws-shim-s3-site-ca-tls-1", "aws-shim-s3-site-ca-tls", "1", "x", "openinfra-ca", "leaf", oldRoot, true),
				),
				"certs-open-infra-ecr.json": items(leafCert("ecr-registry-public-tls", false)),
				"crs-open-infra-ecr.json": items(
					certReq("ecr-registry-public-tls-9", "ecr-registry-public-tls", "9", "x", "openinfra-ca", "leaf", oldRoot, true),
					certReq("ecr-registry-public-tls-10", "ecr-registry-public-tls", "10", "x", "openinfra-ca", "leaf", oldRoot, true),
				),
			})
			if err != nil {
				t.Fatalf("publisher failed: %v\n%s", err, out)
			}
			var ec map[string]any
			if err := json.Unmarshal([]byte(readStub(dir, "applied.json")), &ec); err != nil {
				t.Fatalf("no EnvironmentConfig applied: %v\n%s", err, out)
			}
			if got := ec["data"].(map[string]any)["platformRootCA"]; got != newRoot+"\n" && got != strings.TrimSuffix(newRoot, "\n")+"\n" {
				t.Fatalf("published %q, want the root's revision-3 certificate", got)
			}
			patches := strings.Split(strings.TrimSpace(readStub(dir, "patches.txt")), "\n")
			var renewed []string
			for _, p := range patches {
				if p == "" {
					continue
				}
				who, body, _ := strings.Cut(p, " ")
				renewed = append(renewed, who)
				var ops []map[string]any
				if err := json.Unmarshal([]byte(body), &ops); err != nil {
					t.Fatalf("patch for %s is not a JSON patch: %v\n%s", who, err, body)
				}
				if ops[0]["op"] != "test" || ops[0]["path"] != "/metadata/resourceVersion" || ops[0]["value"] != "42" {
					t.Errorf("%s: the renewal must be guarded by the resourceVersion; got %v", who, ops[0])
				}
				conds, _ := ops[1]["value"].([]any)
				last, _ := conds[len(conds)-1].(map[string]any)
				if ops[1]["path"] != "/status/conditions" || last["type"] != "Issuing" || last["status"] != "True" || last["reason"] != "ManuallyTriggered" {
					t.Errorf("%s: want an Issuing=True ManuallyTriggered condition (cmctl renew); got %v", who, ops[1])
				}
			}
			// openinfra-ca-bundle: its latest READY request (rev 1) is from the old root.
			want := "open-infra-aws-shim/openinfra-ca-bundle,open-infra-ecr/ecr-registry-public-tls"
			if strings.Join(renewed, ",") != want {
				t.Errorf("renewed %v, want %s (current leaves and leaves already issuing untouched)\n%s", renewed, want, out)
			}
		})
	}
}

// A leaf re-issued minutes ago and still signed by another root is not renewed again: the issuer is not
// signing with the root's key (a rotation rolled back without renewing the root), and renewing every run
// would not help. It is reported instead.
func TestPlatformCAPublisher_BacksOffALeafThatStaysStale(t *testing.T) {
	needJQ(t)
	sh := posixShells(t)[0]
	recent := certReq("ecr-2", "ecr-registry-public-tls", "2", "x", "openinfra-ca", "leaf", oldRoot, true)
	recent["metadata"].(map[string]any)["creationTimestamp"] = time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	dir, out, err := runPublisher(t, sh, map[string]any{
		"root-cert.json":            rootCert(3, "openinfra-root-ca-2"),
		"issuer.json":               map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-root-ca-2"}}},
		"crs-cert-manager.json":     items(certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, newRoot, true)),
		"certs-open-infra-ecr.json": items(leafCert("ecr-registry-public-tls", false)),
		"crs-open-infra-ecr.json":   items(certReq("ecr-1", "ecr-registry-public-tls", "1", "x", "openinfra-ca", "leaf", oldRoot, true), recent),
	})
	if err != nil {
		t.Fatalf("publisher failed: %v\n%s", err, out)
	}
	if got := readStub(dir, "patches.txt"); got != "" {
		t.Fatalf("a leaf renewed 5 minutes ago must not be renewed again; patched %q", got)
	}
	if !strings.Contains(out, "WARNING: open-infra-ecr/ecr-registry-public-tls was re-issued") {
		t.Errorf("the stuck leaf must be reported\n%s", out)
	}
}

// Part-way through a key rotation the ClusterIssuer still signs with the old Secret: guests keep the
// root that signs, and no leaf is renewed (it would only be re-signed by the old key).
func TestPlatformCAPublisher_WaitsWhileTheIssuerSignsWithAnotherSecret(t *testing.T) {
	needJQ(t)
	sh := posixShells(t)[0]
	dir, out, err := runPublisher(t, sh, map[string]any{
		"root-cert.json":            rootCert(3, "openinfra-root-ca-2"),
		"issuer.json":               map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-root-ca"}}},
		"crs-cert-manager.json":     items(certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, newRoot, true)),
		"certs-open-infra-ecr.json": items(leafCert("ecr-registry-public-tls", false)),
		"crs-open-infra-ecr.json":   items(certReq("ecr-1", "ecr-registry-public-tls", "1", "x", "openinfra-ca", "leaf", oldRoot, true)),
	})
	if err != nil {
		t.Fatalf("a rotation in progress is not an error: %v\n%s", err, out)
	}
	if readStub(dir, "applied.json") != "" || readStub(dir, "patches.txt") != "" {
		t.Fatalf("nothing may change while the issuer signs with another Secret\n%s", out)
	}
}

// Nothing is published unless it is certificates only, and unless exactly one request is the root's
// current issued revision.
func TestPlatformCAPublisher_RefusesAnythingButTheIssuedRoot(t *testing.T) {
	needJQ(t)
	sh := posixShells(t)[0]
	cases := map[string][]map[string]any{
		"a key in the PEM": {certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer",
			newRoot+"-----BEGIN EC PRIVATE KEY-----\nS0VZ\n-----END EC PRIVATE KEY-----\n", "", true)},
		"only another revision": {certReq("openinfra-root-ca-2", "openinfra-root-ca", "2", rootUID, "openinfra-issuer", oldRoot, "", true)},
		"not ready":             {certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, "", false)},
		"not owned by the root": {certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", "", "openinfra-issuer", newRoot, "", true)},
		"another issuer":        {certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "evil", newRoot, "", true)},
	}
	for name, crs := range cases {
		t.Run(name, func(t *testing.T) {
			dir, out, err := runPublisher(t, sh, map[string]any{
				"root-cert.json":        rootCert(3, "openinfra-root-ca-2"),
				"issuer.json":           map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-root-ca-2"}}},
				"crs-cert-manager.json": items(crs...),
			})
			if err == nil {
				t.Fatalf("want a failed run\n%s", out)
			}
			if readStub(dir, "applied.json") != "" || readStub(dir, "patches.txt") != "" {
				t.Fatalf("nothing may be published or renewed\n%s", out)
			}
		})
	}
}

const awsCAUID = "5a1f00d2-0000-4aaa-8bbb-0a5ca0000001"

func awsCACert(rev int, secret string, ready bool) map[string]any {
	st := "True"
	if !ready {
		st = "False"
	}
	return map[string]any{"metadata": map[string]any{"name": "openinfra-aws-endpoints-ca", "uid": awsCAUID},
		"spec":   map[string]any{"secretName": secret, "issuerRef": map[string]any{"name": "openinfra-issuer", "kind": "ClusterIssuer", "group": "cert-manager.io"}},
		"status": map[string]any{"revision": rev, "conditions": []any{map[string]any{"type": "Ready", "status": st}}}}
}

// The AWS endpoints CA (guest-aws-endpoints.yaml) is published beside the root, from its own current
// revision's request, by the same rules; without one (guest AWS endpoints off) only the root is published;
// and while it cannot be read (not ready, its issuer signing with another Secret, a refused PEM) the one
// published before stays, never dropped or replaced by something unverified.
func TestPlatformCAPublisher_PublishesTheAWSEndpointsCA(t *testing.T) {
	needJQ(t)
	sh := posixShells(t)[0]
	awsCA := pemOf("QVdTQ0E=")
	before := pemOf("QkVGT1JF")
	base := func() map[string]any {
		return map[string]any{
			"root-cert.json": rootCert(3, "openinfra-root-ca-2"),
			"issuer.json":    map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-root-ca-2"}}},
			"crs-cert-manager.json": items(
				certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, newRoot, true),
				certReq("openinfra-aws-endpoints-ca-1", "openinfra-aws-endpoints-ca", "1", awsCAUID, "openinfra-issuer", awsCA, awsCA, true),
				certReq("aws-look-alike", "openinfra-aws-endpoints-ca", "1", "", "openinfra-issuer", pemOf("RVZJTA=="), "", true),
			),
			"aws-issuer.json": map[string]any{"spec": map[string]any{"ca": map[string]any{"secretName": "openinfra-aws-endpoints-ca-1"}}},
			"envcfg.json":     map[string]any{"data": map[string]any{"platformRootCA": newRoot, "awsEndpointsCA": before}},
		}
	}
	published := func(t *testing.T, fx map[string]any) map[string]any {
		t.Helper()
		dir, out, err := runPublisher(t, sh, fx)
		if err != nil {
			t.Fatalf("publisher failed: %v\n%s", err, out)
		}
		var ec map[string]any
		if err := json.Unmarshal([]byte(readStub(dir, "applied.json")), &ec); err != nil {
			t.Fatalf("no EnvironmentConfig applied: %v\n%s", err, out)
		}
		data := ec["data"].(map[string]any)
		if s, _ := data["platformRootCA"].(string); strings.TrimSpace(s) != strings.TrimSpace(newRoot) {
			t.Fatalf("the root must be published as always, got %q", s)
		}
		return data
	}
	same := func(got any, want string) bool {
		s, _ := got.(string)
		return strings.TrimSpace(s) == strings.TrimSpace(want)
	}

	fx := base()
	fx["aws-cert.json"] = awsCACert(1, "openinfra-aws-endpoints-ca-1", true)
	if got := published(t, fx)["awsEndpointsCA"]; !same(got, awsCA) {
		t.Errorf("issued: awsEndpointsCA = %q, want its revision-1 certificate", got)
	}

	fx = base() // no openinfra-aws-endpoints-ca: guest AWS endpoints off
	if got, ok := published(t, fx)["awsEndpointsCA"]; ok {
		t.Errorf("without the CA only the root is published, got awsEndpointsCA %q", got)
	}

	fx = base()
	fx["aws-cert.json"] = awsCACert(2, "openinfra-aws-endpoints-ca-1", false)
	if got := published(t, fx)["awsEndpointsCA"]; !same(got, before) {
		t.Errorf("not ready: the CA published before must stay, got %q", got)
	}

	fx = base()
	fx["aws-cert.json"] = awsCACert(1, "openinfra-aws-endpoints-ca-2", true) // its issuer still signs with -1
	if got := published(t, fx)["awsEndpointsCA"]; !same(got, before) {
		t.Errorf("mid-rotation: the CA published before must stay, got %q", got)
	}

	fx = base()
	fx["aws-cert.json"] = awsCACert(1, "openinfra-aws-endpoints-ca-1", true)
	fx["crs-cert-manager.json"] = items(
		certReq("openinfra-root-ca-3", "openinfra-root-ca", "3", rootUID, "openinfra-issuer", newRoot, newRoot, true),
		certReq("openinfra-aws-endpoints-ca-1", "openinfra-aws-endpoints-ca", "1", awsCAUID, "openinfra-issuer",
			awsCA+"-----BEGIN EC PRIVATE KEY-----\nS0VZ\n-----END EC PRIVATE KEY-----\n", "", true),
	)
	if got := published(t, fx)["awsEndpointsCA"]; !same(got, before) {
		t.Errorf("a key in its PEM is never published; the one before stays, got %q", got)
	}
}
