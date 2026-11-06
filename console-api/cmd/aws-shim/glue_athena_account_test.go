package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// glueAthenaMemberReq is r carrying a member account's identity, as the router puts it on every request.
func glueAthenaMemberReq(r *http.Request) *http.Request {
	ctx := awsidentity.WithIdentity(withAccountHome(r.Context(), memberHome), awsidentity.Current().ForAccount(testMember, memberHome))
	return r.WithContext(ctx)
}

// A member account is refused Glue outright — the shared catalog is the management account's — before the
// catalog is ever called; the management account's Glue is unchanged. Glue is not account-scoped.
func TestGlue_MemberAccountRefused(t *testing.T) {
	fi := newFakeIceberg()
	defer fi.srv.Close()
	fi.addNamespace("sales")
	h := newGlueTestHandler(csWithSAR(true), fi.srv.URL)
	member := iam.Claims{Sub: "bob", Account: testMember}
	for _, op := range []string{"GetDatabases", "GetDatabase", "CreateDatabase", "GetTables", "CreateTable"} {
		w := httptest.NewRecorder()
		h.serve(w, glueAthenaMemberReq(glueRequest(op, `{"Name":"sales","DatabaseName":"sales","DatabaseInput":{"Name":"x"}}`)), member, "r-m")
		assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
		if msg := glueErrorMessage(t, w); !strings.Contains(msg, "not available to member accounts") {
			t.Errorf("%s: message %q does not say why", op, msg)
		}
	}
	// In-process (no identity on the request), a member account's claims are refused all the same.
	w := httptest.NewRecorder()
	h.serve(w, glueRequest("GetDatabases", `{}`), member, "r-m2")
	assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
	if fi.hitCount() != 0 {
		t.Fatalf("the catalog was called %d times for a member account", fi.hitCount())
	}
	w = httptest.NewRecorder()
	h.serve(w, glueRequest("GetDatabase", `{"Name":"sales"}`), glueClaims(), "r-g")
	if w.Code != http.StatusOK {
		t.Errorf("the management account's GetDatabase = %d %s", w.Code, w.Body.String())
	}
	if accountScopedServices["glue"] {
		t.Error("glue must not be account-scoped: its catalog is not kept per account")
	}
}

// A member account is refused Athena outright — the shared engine and catalog are the management
// account's — before Trino is ever called. Athena is not account-scoped.
func TestAthena_MemberAccountRefused(t *testing.T) {
	ft := newFakeTrino()
	defer ft.srv.Close()
	h := newAthenaTestHandler(athenaCS(true, trinoDeploy(1, 1)), ft.srv.URL)
	member := iam.Claims{Sub: "bob", Account: testMember}
	for _, op := range []string{"StartQueryExecution", "GetQueryExecution", "ListWorkGroups", "GetWorkGroup"} {
		w := httptest.NewRecorder()
		h.serve(w, glueAthenaMemberReq(athenaRequest(op, `{"QueryString":"SELECT 1","QueryExecutionId":"x","WorkGroup":"primary"}`)), member, "r-m")
		assertECSErrorType(t, w, http.StatusBadRequest, "AccessDeniedException")
		if msg := athenaErrorMessage(t, w); !strings.Contains(msg, "not available to member accounts") {
			t.Errorf("%s: message %q does not say why", op, msg)
		}
	}
	if ft.count() != 0 {
		t.Fatalf("Trino was called %d times for a member account", ft.count())
	}
	w := httptest.NewRecorder()
	h.serve(w, athenaRequest("ListWorkGroups", `{}`), athenaClaims(), "r-a")
	if w.Code != http.StatusOK {
		t.Errorf("the management account's ListWorkGroups = %d %s", w.Code, w.Body.String())
	}
	if accountScopedServices["athena"] {
		t.Error("athena must not be account-scoped: its engine and catalog are not kept per account")
	}
}
