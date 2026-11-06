package main

// Each account's ECR registry is its own: a member account's repository lives at "<account>/<name>" in
// the backing registry and names its account in its ARN, registryId and repositoryUri; the same name lives
// in both accounts independently, and neither account describes, lists, deletes or pulls the other's.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const ecrDoor = ecrTargetPrefix + "."

func ecrMemberHandler(t *testing.T, registryURL string) *ecrHandler {
	t.Helper()
	h := newECRTestHandler(ecrCS(true, ecrSecret()), registryURL)
	h.authz = doorAccountsAuthz(t)
	return h
}

func repoNames(out map[string]any) []string {
	var names []string
	list, _ := out["repositories"].([]any)
	for _, e := range list {
		m, _ := e.(map[string]any)
		n, _ := m["repositoryName"].(string)
		names = append(names, n)
	}
	return names
}

func TestECRAccounts_EachAccountKeepsItsOwnRepositories(t *testing.T) {
	reg := fakeRegistry(testMember+"/app", map[string]string{}) // the member's app: empty, so it deletes
	defer reg.Close()
	h := ecrMemberHandler(t, reg.URL)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()

	if code, out := mgmt.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "app"}); code != http.StatusOK {
		t.Fatalf("management create: %d %v", code, out)
	}
	if code, out := mgmt.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "ops/tools"}); code != http.StatusOK {
		t.Fatalf("management create: %d %v", code, out)
	}
	// The member account's own "app": the same name, its own repository.
	code, out := member.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "app", "imageTagMutability": "IMMUTABLE"})
	if code != http.StatusOK {
		t.Fatalf("member create of a name the management account has: %d %v", code, out)
	}
	repo, _ := out["repository"].(map[string]any)
	if repo["repositoryArn"] != "arn:aws:ecr:us-east-1:"+testMember+":repository/app" || repo["registryId"] != testMember ||
		repo["repositoryUri"] != "ecr-registry.open-infra-ecr:5000/"+testMember+"/app" {
		t.Fatalf("the member's repository must name its account: %v", repo)
	}
	if code, out := member.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "app"}); code == http.StatusOK ||
		jsonErrType(out) != "RepositoryAlreadyExistsException" || !strings.Contains(out["message"].(string), testMember) {
		t.Fatalf("the member's second create: %d %v", code, out)
	}

	// The management account's records are named, stored and shaped exactly as before accounts.
	cms := h.cs.CoreV1().ConfigMaps(h.ns)
	cm, err := cms.Get(context.Background(), h.repoCMName("app"), metav1.GetOptions{})
	if err != nil || strings.Contains(cm.Data["repo.json"], "account") || cm.Data["account"] != "" || cm.Labels[ecrAccountLabel] != "" {
		t.Fatalf("the management account's record must not change: %v %v", cm, err)
	}
	if mcm, err := cms.Get(context.Background(), h.repoCMName(testMember+":app"), metav1.GetOptions{}); err != nil ||
		mcm.Data["account"] != testMember || mcm.Labels[ecrAccountLabel] != testMember {
		t.Fatalf("the member's record is kept under its account key and carries its account: %v %v", mcm, err)
	}
	_, out = mgmt.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{"repositoryNames": []any{"app"}})
	mrepo := out["repositories"].([]any)[0].(map[string]any)
	if mrepo["repositoryArn"] != "arn:aws:ecr:us-east-1:open-infra:repository/app" || mrepo["registryId"] != "open-infra" ||
		mrepo["repositoryUri"] != "ecr-registry.open-infra-ecr:5000/app" || mrepo["imageTagMutability"] != "MUTABLE" {
		t.Fatalf("the management account's repository is unchanged: %v", mrepo)
	}

	// Listings: each account its own.
	if _, out := mgmt.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{}); strings.Join(sortedStrings(repoNames(out)), ",") != "app,ops/tools" {
		t.Fatalf("the management account lists its own repositories alone: %v", repoNames(out))
	}
	if _, out := member.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{}); strings.Join(repoNames(out), ",") != "app" {
		t.Fatalf("the member account lists its own repositories alone: %v", repoNames(out))
	}
	_, out = member.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{"repositoryNames": []any{"app"}})
	if r := out["repositories"].([]any)[0].(map[string]any); r["imageTagMutability"] != "IMMUTABLE" || r["registryId"] != testMember {
		t.Fatalf("the member reads its own app, not the management account's: %v", r)
	}
	// The management account's other repository is not the member's.
	if code, out := member.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{"repositoryNames": []any{"ops/tools"}}); code == http.StatusOK ||
		jsonErrType(out) != "RepositoryNotFoundException" || !strings.Contains(out["message"].(string), testMember) {
		t.Fatalf("a member must not see the management account's repository: %d %v", code, out)
	}
	if code, out := member.call(t, h.serve, ecrDoor+"PutImageTagMutability", map[string]any{"repositoryName": "ops/tools", "imageTagMutability": "IMMUTABLE"}); code == http.StatusOK {
		t.Fatalf("a member must not change the management account's repository: %v", out)
	}

	// Deleting the member's app leaves the management account's.
	if code, out := member.call(t, h.serve, ecrDoor+"DeleteRepository", map[string]any{"repositoryName": "app"}); code != http.StatusOK {
		t.Fatalf("member delete: %d %v", code, out)
	}
	if code, _ := mgmt.call(t, h.serve, ecrDoor+"DescribeRepositories", map[string]any{"repositoryNames": []any{"app"}}); code != http.StatusOK {
		t.Fatal("the member's delete removed the management account's repository")
	}
	if code, out := member.call(t, h.serve, ecrDoor+"DeleteRepository", map[string]any{"repositoryName": "ops/tools"}); code == http.StatusOK ||
		jsonErrType(out) != "RepositoryNotFoundException" {
		t.Fatalf("a member must not delete the management account's repository: %d %v", code, out)
	}
}

func sortedStrings(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// A member account's images are read from its own registry path; the management account's from the
// registry's root, as before.
func TestECRAccounts_ImagesComeFromTheAccountsRegistryPath(t *testing.T) {
	reg := fakeRegistry(testMember+"/app", map[string]string{"v1": "sha256:aaa"})
	defer reg.Close()
	h := ecrMemberHandler(t, reg.URL)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	for _, c := range []doorCaller{mgmt, member} {
		if code, out := c.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "app"}); code != http.StatusOK {
			t.Fatalf("create: %d %v", code, out)
		}
	}
	code, out := member.call(t, h.serve, ecrDoor+"DescribeImages", map[string]any{"repositoryName": "app"})
	details, _ := out["imageDetails"].([]any)
	if code != http.StatusOK || len(details) != 1 || details[0].(map[string]any)["registryId"] != testMember {
		t.Fatalf("the member's images are its registry path's: %d %v", code, out)
	}
	if code, out := member.call(t, h.serve, ecrDoor+"ListImages", map[string]any{"repositoryName": "app"}); code != http.StatusOK || len(out["imageIds"].([]any)) != 1 {
		t.Fatalf("member list images: %d %v", code, out)
	}
	// The management account's app is the registry root's "app", which holds nothing here (404 tags/list).
	if code, out := mgmt.call(t, h.serve, ecrDoor+"ListImages", map[string]any{"repositoryName": "app"}); code == http.StatusOK && len(out["imageIds"].([]any)) != 0 {
		t.Fatalf("the management account read the member's images: %v", out)
	}
}

// The management account's registry is the root; a name whose first segment is another account's id is in
// that account's registry, so the management account can neither create nor reach it.
func TestECRAccounts_ManagementCannotReachIntoAMemberRegistry(t *testing.T) {
	h := ecrMemberHandler(t, "")
	mgmt := mgmtDoorCaller()
	code, out := mgmt.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": testMember + "/app"})
	if code == http.StatusOK || jsonErrType(out) != "InvalidParameterException" {
		t.Fatalf("the management account created a repository in a member account's registry: %d %v", code, out)
	}
	// Its own id as a first segment is just a name.
	if code, out := mgmt.call(t, h.serve, ecrDoor+"CreateRepository", map[string]any{"repositoryName": "open-infra/app"}); code != http.StatusOK {
		t.Fatalf("an ordinary nested name: %d %v", code, out)
	}
	if !ecrMemberRegistryName(testMember+"/x") || ecrMemberRegistryName("000000000000/x") || ecrMemberRegistryName("12345/x") ||
		ecrMemberRegistryName(testMember) {
		t.Fatal("ecrMemberRegistryName")
	}
}

// The registry token realm grants a member account's credential its own registry's paths alone, and the
// management account's credential none of a member account's.
func TestECRAccounts_TokenScopesStayInTheAccountsRegistry(t *testing.T) {
	h := tokenModeECR(t, true, doorAccountsAuthz(t))
	member, err := h.signer.mintCaller(ecrCaller{Sub: "bob", Account: testMember, Home: memberHome}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := realmGrant(t, h, member, "repository:"+testMember+"/app:pull,push", "repository:app:pull",
		"repository:955555555555/app:pull")
	if !equalGrants(got, map[string][]string{testMember + "/app": {"pull", "push"}}) {
		t.Fatalf("a member account is granted its own registry's paths alone, got %v", got)
	}
	alice, err := h.signer.mintCaller(ecrCaller{Sub: "alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = realmGrant(t, h, alice, "repository:app:pull", "repository:"+testMember+"/app:pull")
	if !equalGrants(got, map[string][]string{"app": {"pull"}}) {
		t.Fatalf("the management account is granted its own paths, never a member account's, got %v", got)
	}
}

// A member account's GetAuthorizationToken carries its account; without per-repository token auth the
// shared registry credential (which reaches every account's registry) is never handed to a member account.
func TestECRAccounts_MemberTokenNeedsPerRepositoryAuth(t *testing.T) {
	h := ecrMemberHandler(t, "")
	code, out := memberDoorCaller().call(t, h.serve, ecrDoor+"GetAuthorizationToken", map[string]any{})
	if code == http.StatusOK || jsonErrType(out) != "AccessDeniedException" {
		t.Fatalf("a member account got the shared registry credential: %d %v", code, out)
	}
	if code, _ := mgmtDoorCaller().call(t, h.serve, ecrDoor+"GetAuthorizationToken", map[string]any{}); code != http.StatusOK {
		t.Fatal("the management account keeps its credential")
	}

	h = tokenModeECR(t, true, doorAccountsAuthz(t))
	member := memberDoorCaller()
	w := httptest.NewRecorder()
	r := ecrRequest("GetAuthorizationToken", `{}`).WithContext(member.ctx)
	h.serve(w, r, iam.Claims{Sub: "bob", Account: testMember}, "req")
	var resp struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"authorizationData"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.AuthorizationData) != 1 {
		t.Fatalf("member token: %d %s", w.Code, w.Body.String())
	}
}
