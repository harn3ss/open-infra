package accounts

import (
	"context"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"
)

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// A derived id is 12 digits starting with 9, stable for a namespace, and different for the next attempt.
func TestDeriveAccountID(t *testing.T) {
	a := DeriveAccountID("team-a", 0)
	if !regexp.MustCompile(`^9[0-9]{11}$`).MatchString(a) || !ValidAccountID(a) {
		t.Fatalf("derived id %q is not 9 + 11 digits", a)
	}
	if DeriveAccountID("team-a", 0) != a {
		t.Error("the derived id must be stable for a namespace")
	}
	if DeriveAccountID("team-b", 0) == a || DeriveAccountID("team-a", 1) == a {
		t.Error("another namespace, or the next attempt, must derive another id")
	}
}

// A taken id is skipped (collision-checked); a namespace whose every candidate is taken is an error.
func TestNewAccountID_SkipsTakenIDs(t *testing.T) {
	first := DeriveAccountID("team-a", 0)
	got, err := NewAccountID("team-a", func(id string) bool { return id == first })
	if err != nil || got == first || got != DeriveAccountID("team-a", 1) {
		t.Fatalf("NewAccountID = %q, %v; want the second candidate", got, err)
	}
	if _, err := NewAccountID("team-a", func(string) bool { return true }); err == nil {
		t.Error("every candidate taken must be an error")
	}
}

func TestIsPlatformNamespace(t *testing.T) {
	for _, n := range []string{"kube-system", "kube-public", "knative-serving", "openinfra-images", "argocd", "monitoring", "open-infra-aws-shim"} {
		if !IsPlatformNamespace(n) {
			t.Errorf("%s is platform-internal", n)
		}
	}
	for _, n := range append([]string{"default", "team-a", "main-dev"}, ManagementNamespaces...) {
		if IsPlatformNamespace(n) {
			t.Errorf("%s is a tenant namespace", n)
		}
	}
}

func TestDirectory(t *testing.T) {
	d := NewDirectory("000000000000")
	d.Observe(ns("open-infra-console", map[string]string{LabelAccountID: "000000000000", LabelAccountHome: "true"}))
	d.Observe(ns("team-a", map[string]string{LabelAccountID: "912345678901", LabelAccountHome: "true"}))
	d.Observe(ns("team-a-data", map[string]string{LabelAccountID: "912345678901"}))
	d.Observe(ns("kube-system", map[string]string{LabelAccountID: "912345678901"})) // never an account's

	if got := d.AccountOf("team-a-data"); got != "912345678901" {
		t.Errorf("AccountOf(team-a-data) = %q", got)
	}
	if got := d.AccountOf("unlabeled"); got != "000000000000" {
		t.Errorf("an unlabeled tenant namespace belongs to the management account, got %q", got)
	}
	if got := d.AccountOf("kube-system"); got != "" {
		t.Errorf("a platform namespace belongs to no account, got %q", got)
	}
	if d.Labeled("unlabeled") || !d.Labeled("team-a") {
		t.Error("Labeled must report the explicit label only")
	}
	if h, ok := d.HomeOf("912345678901"); !ok || h != "team-a" {
		t.Errorf("HomeOf(member) = %q, %v", h, ok)
	}
	if h, ok := d.HomeOf("000000000000"); !ok || h != "open-infra-console" {
		t.Errorf("HomeOf(management) = %q, %v", h, ok)
	}
	if _, ok := d.HomeOf("999999999999"); ok {
		t.Error("an unknown account has no home")
	}
	if got := d.NamespacesOf("912345678901"); !slices.Equal(got, []string{"team-a", "team-a-data"}) {
		t.Errorf("NamespacesOf = %v", got)
	}
	if got := d.Accounts(); !slices.Equal(got, []string{"000000000000", "912345678901"}) {
		t.Errorf("Accounts = %v (management first)", got)
	}
	if !d.Known("912345678901") || d.Known("999999999999") || !d.Known("000000000000") || !d.IsManagement("000000000000") {
		t.Error("Known / IsManagement")
	}

	// Suspension follows the label; relabeling moves a namespace; deletion forgets it.
	d.Observe(ns("team-a", map[string]string{LabelAccountID: "912345678901", LabelAccountHome: "true", LabelAccountStatus: StatusSuspended}))
	if !d.Suspended("912345678901") {
		t.Error("a SUSPENDED label suspends the account")
	}
	d.Observe(ns("team-a-data", map[string]string{LabelAccountID: "923456789012"}))
	if got := d.NamespacesOf("912345678901"); !slices.Equal(got, []string{"team-a"}) {
		t.Errorf("after the move NamespacesOf = %v", got)
	}
	d.Forget("team-a")
	if d.Known("912345678901") {
		t.Error("an account with no namespace left is forgotten")
	}
	if _, ok := d.HomeOf("912345678901"); ok {
		t.Error("its home is forgotten with it")
	}
}

// Watch fills the directory from the cluster's labeled namespaces and follows changes.
func TestWatch(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ns("team-a", map[string]string{LabelAccountID: "912345678901", LabelAccountHome: "true"}),
		ns("plain", nil),
	)
	d := NewDirectory("000000000000")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Watch(ctx, cs, d, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := d.AccountOf("team-a"); got != "912345678901" {
		t.Fatalf("after the initial listing AccountOf(team-a) = %q", got)
	}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, ns("team-b", map[string]string{LabelAccountID: "923456789012", LabelAccountHome: "true"}), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.AccountOf("team-b") != "923456789012" {
		if time.Now().After(deadline) {
			t.Fatal("a namespace labeled after the start was not seen")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The Account XRD's admission refuses exactly the platform namespaces this package treats as such.
func TestXRDRefusesThePlatformNamespaces(t *testing.T) {
	raw, err := os.ReadFile("../../../platform/abstraction/account-xrd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var xrd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Validations []struct {
									Rule string `json:"rule"`
								} `json:"x-kubernetes-validations"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &xrd); err != nil {
		t.Fatal(err)
	}
	rule := ""
	for _, v := range xrd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Validations {
		if strings.Contains(v.Rule, "startsWith") {
			rule = v.Rule
		}
	}
	if rule == "" {
		t.Fatal("no platform-namespace rule in the Account XRD")
	}
	listPart := rule[strings.Index(rule, "[")+1 : strings.Index(rule, "]")]
	var names []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(listPart, -1) {
		names = append(names, m[1])
	}
	var prefixes []string
	for _, m := range regexp.MustCompile(`startsWith\('([^']+)'\)`).FindAllStringSubmatch(rule, -1) {
		prefixes = append(prefixes, m[1])
	}
	want := slices.Clone(PlatformNamespaces)
	sort.Strings(want)
	sort.Strings(names)
	if !slices.Equal(names, want) {
		t.Errorf("the XRD refuses %v, the package treats %v as platform namespaces", names, want)
	}
	wantP := slices.Clone(PlatformPrefixes)
	sort.Strings(wantP)
	sort.Strings(prefixes)
	if !slices.Equal(prefixes, wantP) {
		t.Errorf("the XRD refuses prefixes %v, the package %v", prefixes, wantP)
	}
}

// install.sh bootstraps the management account with exactly ManagementNamespaces.
func TestInstallBootstrapsTheManagementNamespaces(t *testing.T) {
	raw, err := os.ReadFile("../../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "kind: Account\n")
	if i < 0 {
		t.Fatal("install.sh applies no management Account")
	}
	block := s[i:]
	block = block[strings.Index(block, "namespaces:\n")+len("namespaces:\n"):]
	var got []string
	for _, ln := range strings.Split(block, "\n") {
		item, ok := strings.CutPrefix(strings.TrimSpace(ln), "- ")
		if !ok {
			break
		}
		got = append(got, item)
	}
	if !slices.Equal(got, ManagementNamespaces) {
		t.Errorf("install.sh bootstraps %v, the package's ManagementNamespaces are %v", got, ManagementNamespaces)
	}
}
