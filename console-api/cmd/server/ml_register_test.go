package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// mlReq builds a signed-in POST to the register endpoint with chi params attached.
func mlReq(ns, name, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost,
		"/api/trainingjobs/"+ns+"/"+name+"/register", strings.NewReader(body))
	claims := sessionClaims{}
	claims.Sub = "alice"
	claims.Role = "poweruser"
	r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims))
	return withParams(r, map[string]string{"namespace": ns, "name": name})
}

// The #55 crux: a user who can run TrainingJobs but is not authorized to create ModelPackages
// must be denied here, by the same SubjectAccessReview every BFF mutation uses. The fake clientset
// denies every SAR by default, so this signed-in poweruser is refused 403 — and because authorize()
// returns before any RESTClient call, no ModelPackage is ever created. A train-capable,
// serve-incapable identity cannot promote through this path.
func TestRegisterDeniesUnauthorized(t *testing.T) {
	cs := fake.NewSimpleClientset() // default: every SAR denied
	auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	rec := httptest.NewRecorder()
	handleTrainingJobRegister(cs, auth, slog.New(slog.DiscardHandler)).
		ServeHTTP(rec, mlReq("ml", "mnist-train", `{"modelName":"mnist","image":"reg/serve:1"}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized register = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// Once past the gate, the serving image and model name are required (the serving container is not
// the training container, so it can never be inferred), and 8080 is rejected (reserved for the
// endpoint proxy). These validations run before anything is read or created.
func TestRegisterValidatesInput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing modelName", `{"image":"reg/serve:1"}`},
		{"missing serving image", `{"modelName":"mnist"}`},
		{"port 8080 reserved", `{"modelName":"mnist","image":"reg/serve:1","port":8080}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			allowSAR(cs) // pass the gate so validation is what's under test
			auth := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

			rec := httptest.NewRecorder()
			handleTrainingJobRegister(cs, auth, slog.New(slog.DiscardHandler)).
				ServeHTTP(rec, mlReq("ml", "mnist-train", c.body))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400; body=%s", c.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestModelPackageName(t *testing.T) {
	cases := []struct{ model, version, want string }{
		{"fraud-detector", "3", "fraud-detector-3"},
		{"MNIST", "v1.2", "mnist-v1-2"},
		{"my model!", "2026", "my-model-2026"}, // trailing junk trimmed before the version join
	}
	for _, c := range cases {
		if got := modelPackageName(c.model, c.version); got != c.want {
			t.Errorf("modelPackageName(%q,%q) = %q, want %q", c.model, c.version, got, c.want)
		}
	}
}
