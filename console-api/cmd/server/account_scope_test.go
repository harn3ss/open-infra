package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/watch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const memberAcct = "111122223333"

// seedNamespaces gives z's cluster: the management account's console home and an unclaimed tenant
// namespace, one labelled for it explicitly, a member account's two (its home labelled), another
// account's, and platform namespaces (never an account's, whatever their labels).
func seedNamespaces(t *testing.T, z *consoleAuthz) {
	t.Helper()
	add := func(name string, labels map[string]string) {
		if _, err := z.cs.CoreV1().Namespaces().Create(context.Background(),
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	add("open-infra-console", nil)
	add("default", nil)
	add("mgmt-labelled", map[string]string{accounts.LabelAccountID: "000000000000"})
	add("team-a", map[string]string{accounts.LabelAccountID: memberAcct, accounts.LabelAccountHome: "true"})
	add("team-a-data", map[string]string{accounts.LabelAccountID: memberAcct})
	add("team-b", map[string]string{accounts.LabelAccountID: "444455556666"})
	add("kube-system", nil)
	add("monitoring", map[string]string{accounts.LabelAccountID: memberAcct})
}

func memberClaims(name string) sessionClaims {
	c := userClaims(name)
	c.Account = memberAcct
	return c
}

func TestAccountNamespaces(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)
	for _, c := range []struct {
		acct, home string
		want       []string
	}{
		{"000000000000", "open-infra-console", []string{"default", "mgmt-labelled", "open-infra-console"}},
		{memberAcct, "team-a", []string{"team-a", "team-a-data"}},
		{"999999999999", "", nil},
	} {
		names, home, err := z.accountNamespaces(context.Background(), c.acct)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(names, ",") != strings.Join(c.want, ",") || home != c.home {
			t.Errorf("%s: %v home %q, want %v home %q", c.acct, names, home, c.want, c.home)
		}
	}
}

// listItem is one object of a fake list answer.
func listItem(ns, name string) map[string]any {
	return map[string]any{"metadata": map[string]any{"namespace": ns, "name": name}}
}

// fakeK8s answers lists: cluster-wide with every bucket (or 403 when clusterWide is false), and each
// namespace's own, each with its own resourceVersion. It records the paths asked.
type fakeK8s struct {
	clusterWide bool
	mu          sync.Mutex // the account list fans out: requests arrive concurrently
	asked       []string
}

func (f *fakeK8s) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, k8sPrefix)
	f.mu.Lock()
	f.asked = append(f.asked, path+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	all := map[string][]string{"default": {"d1"}, "open-infra-console": {"c1"}, "team-a": {"a1", "a2"},
		"team-a-data": {"ad1"}, "team-b": {"b1"}}
	rvs := map[string]string{"team-a": "120", "team-a-data": "95"}
	var items []any
	rv := "200"
	if path == "/apis/openinfra.dev/v1/buckets" {
		if !f.clusterWide {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errorCode":"AccessDeniedException"}`))
			return
		}
		for ns, names := range all {
			for _, n := range names {
				items = append(items, listItem(ns, n))
			}
		}
	} else {
		ns := strings.Split(strings.TrimPrefix(path, "/apis/openinfra.dev/v1/namespaces/"), "/")[0]
		for _, n := range all[ns] {
			items = append(items, listItem(ns, n))
		}
		rv = rvs[ns]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "openinfra.dev/v1", "kind": "BucketList",
		"metadata": map[string]any{"resourceVersion": rv}, "items": items})
}

func listNames(t *testing.T, body []byte) ([]string, string) {
	t.Helper()
	var doc struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []struct {
			Metadata struct{ Namespace, Name string } `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	var out []string
	for _, it := range doc.Items {
		out = append(out, it.Metadata.Namespace+"/"+it.Metadata.Name)
	}
	sort.Strings(out)
	return out, doc.Metadata.ResourceVersion
}

const accountBuckets = "/api/k8s/apis/openinfra.dev/v1/buckets?scope=account"

// Where the caller may list cluster-wide, one list is asked and filtered to the account (the management
// account here: its labelled and unclaimed namespaces, never another account's or a platform one).
func TestAccountList_FiltersAClusterWideList(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)
	k := &fakeK8s{clusterWide: true}
	got := serve(z.proxyHandler(k8sPrefix, k), as(httptest.NewRequest(http.MethodGet, accountBuckets, nil), userClaims("alice")))
	if got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body)
	}
	names, rv := listNames(t, got.Body.Bytes())
	if strings.Join(names, ",") != "default/d1,open-infra-console/c1" || rv != "200" {
		t.Errorf("management account's buckets: %v rv %s", names, rv)
	}
	if len(k.asked) != 1 || strings.Contains(k.asked[0], "scope") {
		t.Errorf("asked %v: want one cluster-wide list, without the console's scope parameter", k.asked)
	}
}

// Where the API server refuses the cluster-wide list (an account's RBAC is per namespace), each of the
// account's namespaces is asked and the answers merged, at the earliest resourceVersion.
func TestAccountList_FansOutWhenRefusedClusterWide(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)
	k := &fakeK8s{}
	got := serve(z.proxyHandler(k8sPrefix, k), as(httptest.NewRequest(http.MethodGet, accountBuckets, nil), memberClaims("bob")))
	if got.Code != 200 {
		t.Fatalf("%d %s", got.Code, got.Body)
	}
	names, rv := listNames(t, got.Body.Bytes())
	if strings.Join(names, ",") != "team-a-data/ad1,team-a/a1,team-a/a2" || rv != "95" {
		t.Errorf("member account's buckets: %v rv %s", names, rv)
	}
	if len(k.asked) != 3 {
		t.Errorf("asked %v: want the cluster-wide list, then the account's two namespaces", k.asked)
	}
}

// In enforce, the IAM gate decides before anything is asked of the API server.
func TestAccountList_IAMDecidesFirst(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)
	k := &fakeK8s{clusterWide: true}
	got := serve(z.proxyHandler(k8sPrefix, k), as(httptest.NewRequest(http.MethodGet, accountBuckets, nil), userClaims("nobody")))
	if got.Code != 403 || errorCode(t, got) != "AccessDeniedException" || len(k.asked) != 0 {
		t.Errorf("no policy: %d %s, asked %v", got.Code, got.Body, k.asked)
	}
	bad := serve(z.proxyHandler(k8sPrefix, k), as(httptest.NewRequest(http.MethodGet,
		"/api/k8s/apis/openinfra.dev/v1/namespaces/team-a/buckets?scope=account", nil), userClaims("nobody")))
	if bad.Code != 400 {
		t.Errorf("scope=account on a namespaced list: %d, want 400", bad.Code)
	}
}

// fakeWatchRT is an API server whose watch streams one bucket event per namespace and a bookmark.
type fakeWatchRT struct{}

func (fakeWatchRT) RoundTrip(*http.Request) (*http.Response, error) {
	lines := []string{
		`{"type":"ADDED","object":{"kind":"Bucket","metadata":{"name":"a1","namespace":"team-a","resourceVersion":"5"}}}`,
		`{"type":"ADDED","object":{"kind":"Bucket","metadata":{"name":"d1","namespace":"default","resourceVersion":"6"}}}`,
		`{"type":"ADDED","object":{"kind":"Bucket","metadata":{"name":"b1","namespace":"team-b","resourceVersion":"7"}}}`,
		`{"type":"BOOKMARK","object":{"kind":"Bucket","metadata":{"resourceVersion":"8"}}}`,
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(strings.Join(lines, "\n") + "\n"))}, nil
}

func watchBody(t *testing.T, z *consoleAuthz, query string, c sessionClaims) (int, string) {
	t.Helper()
	host, _ := url.Parse("http://k8s.test")
	h := z.watchHandler(watch.New(host, fakeWatchRT{}, slog.New(slog.NewTextHandler(io.Discard, nil))))
	got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/watch?"+query, nil), c))
	return got.Code, got.Body.String()
}

func TestAccountWatch_FilteredToTheAccount(t *testing.T) {
	all := "path=" + url.QueryEscape("/apis/openinfra.dev/v1/buckets")
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)

	code, body := watchBody(t, z, all+"&scope=account", memberClaims("bob"))
	if code != 200 || !strings.Contains(body, `"a1"`) || strings.Contains(body, `"d1"`) || strings.Contains(body, `"b1"`) ||
		!strings.Contains(body, "BOOKMARK") {
		t.Errorf("scope=account for the member account: %d\n%s", code, body)
	}
	// Legacy, no scope: the whole stream, as before.
	if _, body := watchBody(t, z, all, memberClaims("bob")); !strings.Contains(body, `"d1"`) || !strings.Contains(body, `"b1"`) {
		t.Errorf("legacy cluster-wide watch was filtered:\n%s", body)
	}
	// One path per watch: the gate authorizes only one.
	if code, _ := watchBody(t, z, all+"&path="+url.QueryEscape("/api/v1/secrets"), userClaims("alice")); code != 400 {
		t.Errorf("two paths: %d, want 400", code)
	}
}

// In enforce, a cluster-wide watch carries only the caller's account (the stream reads with the
// console's ServiceAccount), unless the caller is the operator or root.
func TestAccountWatch_EnforceKeepsAClusterWideWatchInTheAccount(t *testing.T) {
	all := "path=" + url.QueryEscape("/apis/openinfra.dev/v1/buckets")
	docs := map[string]string{"admin": adminDoc, "s3": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`}
	attach := map[string][]string{"User::admin": {"admin"}, "User::team-a/bob": {"s3"}}
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, docs, attach), true)
	seedNamespaces(t, z)

	bob := memberClaims("team-a/bob")
	code, body := watchBody(t, z, all, bob)
	if code != 200 || !strings.Contains(body, `"a1"`) || strings.Contains(body, `"d1"`) || strings.Contains(body, `"b1"`) {
		t.Errorf("a member account's principal watching cluster-wide: %d\n%s", code, body)
	}
	if _, body := watchBody(t, z, all, userClaims("admin")); !strings.Contains(body, `"b1"`) || !strings.Contains(body, `"a1"`) {
		t.Errorf("the operator's cluster-wide watch was filtered:\n%s", body)
	}
	if _, body := watchBody(t, z, all+"&scope=account", userClaims("admin")); strings.Contains(body, `"b1"`) || !strings.Contains(body, `"d1"`) {
		t.Errorf("scope=account is the operator's own account too:\n%s", body)
	}
}

// /api/auth/me says where the account's resources are: its region, namespaces and home.
func TestMe_AccountContext(t *testing.T) {
	z := newTestAuthz(t, iamauthz.ModeLegacy, testWorld(t, nil, nil), true)
	seedNamespaces(t, z)
	z.auth.sessionKey = []byte("test-session-key")
	c := memberClaims("bob")
	tok, err := z.auth.issueClaims(c.Claims)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	w := httptest.NewRecorder()
	handleMe(z.auth)(w, r)
	var body struct {
		Account, Region, HomeNamespace string
		Namespaces                     []string
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Account != memberAcct || body.Region != "us-east-1" || body.HomeNamespace != "team-a" ||
		strings.Join(body.Namespaces, ",") != "team-a,team-a-data" {
		t.Errorf("account context: %s", w.Body)
	}
}
