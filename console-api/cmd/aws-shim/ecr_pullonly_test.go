package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harn3ss/open-infra/policyengine"
)

// A role whose only ECR access is the AmazonEC2ContainerRegistryPullOnly managed policy (as cfn attaches
// it: the policy document imported into data-plane statements) can log in and pull, but not describe or
// list repositories: on AWS DescribeRepositories needs ecr:DescribeRepositories, which PullOnly lacks.
func TestECR_PullOnlyRole_CannotDescribeRepositories(t *testing.T) {
	stmts, unsupported, err := policyengine.ImportAWS(`{"Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":"*"}]}`)
	if err != nil || len(unsupported) > 0 {
		t.Fatalf("import: %v %v", err, unsupported)
	}
	h := tokenModeECR(t, true, roleChecker(stmts...))
	if w, _ := getAuthToken(t, h, ecrRoleClaims()); w.Code != http.StatusOK {
		t.Fatalf("PullOnly must allow GetAuthorizationToken: %d %s", w.Code, w.Body)
	}
	for _, body := range []string{`{}`, `{"repositoryNames":["app"]}`} {
		w := httptest.NewRecorder()
		h.serve(w, ecrRequest("DescribeRepositories", body), ecrRoleClaims(), "req-d")
		assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
	}
}
