package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/harn3ss/open-infra/console-api/internal/guac"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/remotedesktop"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

const rdTestNS = "open-infra-console"

// fakeRDSession stands in for guacd: it shows one frame, then waits for the browser to leave.
type fakeRDSession struct{ creds remotedesktop.Credentials }

func (f *fakeRDSession) Relay(_ context.Context, b remotedesktop.Browser, h *remotedesktop.Handle, _ remotedesktop.RelayOptions) (string, string) {
	_ = b.Send(guac.New("", h.Connection().ConnectionID).String() + guac.New("sync", "1").String())
	for {
		if _, err := b.Receive(); err != nil {
			return remotedesktop.StatusDisconnected, "the browser closed the connection"
		}
	}
}

// rdFixture is the Remote Desktop routes behind z's gate (nil: none), over an instance with os and the
// given state.
func rdFixture(t *testing.T, z *consoleAuthz, os string, running bool) (*remoteDesktop, http.Handler, *fakeRDSession) {
	t.Helper()
	sess := &fakeRDSession{}
	d := &remoteDesktop{z: z, store: &remotedesktop.Store{CS: fake.NewClientset(), NS: rdTestNS}, holder: "console-0", logger: testLogger(),
		vmAccount: func(context.Context, string) string { return iam.ManagementAccount },
		instance: func(context.Context, string, string) (rdInstance, error) {
			return rdInstance{ID: "i-0123456789abcdef0", OS: os}, nil
		},
		running: func(context.Context, string, string) error {
			if running {
				return nil
			}
			return vmconsole.ErrNotRunning
		},
	}
	d.connect = func(_ context.Context, _, _ string, cr remotedesktop.Credentials, _ guac.Size, _ string) (rdSession, error) {
		sess.creds = cr
		return sess, nil
	}
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) {
		reg := func(method, path, action string, hf http.HandlerFunc) {
			if z == nil {
				api.MethodFunc(method, path, hf)
				return
			}
			z.handle(api, apiPrefix, method, path, 0, action, nil, hf)
		}
		reg(http.MethodGet, "/vms/{namespace}/{name}/remote-desktop/check", "ssm-guiconnect:StartConnection", d.handleCheck())
		reg(http.MethodGet, "/vms/{namespace}/{name}/remote-desktop", "ssm-guiconnect:StartConnection", d.handleConnect())
		reg(http.MethodGet, "/remote-desktop/connections", "ssm-guiconnect:ListConnections", d.handleList())
		reg(http.MethodGet, "/remote-desktop/connections/{id}", "ssm-guiconnect:GetConnection", d.handleGet())
		reg(http.MethodPost, "/remote-desktop/connections/{id}/cancel", "ssm-guiconnect:CancelConnection", d.handleCancel())
	})
	return d, r, sess
}

const rdCheckPath = "/api/vms/apps/win/remote-desktop/check"

// Connecting is ssm-guiconnect:StartConnection and ssm:StartSession on the instance and on the
// port-forwarding document, as on AWS: a policy missing any of the three is refused with AccessDenied
// naming it.
func TestRemoteDesktop_ConnectingIsStartConnectionAndStartSession(t *testing.T) {
	guiconnect := `{"Effect":"Allow","Action":"ssm-guiconnect:*","Resource":"*"}`
	onInstance := `{"Effect":"Allow","Action":"ssm:StartSession","Resource":"arn:aws:ec2:*:*:instance/*"}`
	onDocument := `{"Effect":"Allow","Action":"ssm:StartSession","Resource":"arn:aws:ssm:*::document/AWS-StartPortForwardingSession"}`
	doc := func(stmts ...string) string {
		return `{"Version":"2012-10-17","Statement":[` + strings.Join(stmts, ",") + `]}`
	}
	for _, c := range []struct {
		name, policy, deniedAction, deniedOn string
	}{
		{"no StartConnection", doc(onInstance, onDocument), "ssm-guiconnect:StartConnection", "*"},
		{"no StartSession on the instance", doc(guiconnect, onDocument), "ssm:StartSession", ":instance/win"},
		{"no StartSession on the document", doc(guiconnect, onInstance), "ssm:StartSession", "document/AWS-StartPortForwardingSession"},
		{"all three", doc(guiconnect, onInstance, onDocument), "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := testWorld(t, map[string]string{"rdp": c.policy}, map[string][]string{"User::alice": {"rdp"}})
			z := newTestAuthz(t, iamauthz.ModeEnforce, w, true)
			_, h, _ := rdFixture(t, z, "windows-server-2022", true)
			rec := serve(h, as(httptest.NewRequest(http.MethodGet, rdCheckPath, nil), userClaims("alice")))
			if c.deniedAction == "" {
				if rec.Code != http.StatusOK {
					t.Fatalf("allowed: %d %s", rec.Code, rec.Body.String())
				}
				return
			}
			var m map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &m)
			if rec.Code != http.StatusForbidden || m["errorCode"] != "AccessDeniedException" || m["action"] != c.deniedAction || !strings.Contains(m["resource"], c.deniedOn) {
				t.Fatalf("want AccessDenied for %s on %s: %d %s", c.deniedAction, c.deniedOn, rec.Code, rec.Body.String())
			}
			// The connection itself is refused the same way, before any websocket.
			rec = serve(h, as(httptest.NewRequest(http.MethodGet, strings.TrimSuffix(rdCheckPath, "/check"), nil), userClaims("alice")))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("the connection: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The check answers why a connection can't start: not Windows, not running, the account at its quota.
func TestRemoteDesktop_Check(t *testing.T) {
	check := func(h http.Handler) (int, map[string]any) {
		rec := serve(h, httptest.NewRequest(http.MethodGet, rdCheckPath, nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	_, linux, _ := rdFixture(t, nil, "ubuntu-24.04", true)
	if code, m := check(linux); code != 400 || m["errorCode"] != "ValidationException" {
		t.Errorf("a Linux instance: %d %v", code, m)
	}
	_, stopped, _ := rdFixture(t, nil, "windows-server-2022", false)
	if code, m := check(stopped); code != 400 || m["errorCode"] != "TargetNotConnected" {
		t.Errorf("a stopped instance: %d %v", code, m)
	}
	d, h, _ := rdFixture(t, nil, "windows-server-2022", true)
	if code, m := check(h); code != 200 || m["instanceId"] != "i-0123456789abcdef0" || m["maxDurationMinutes"] != float64(60) {
		t.Errorf("ready: %d %v", code, m)
	}
	for i := 0; i < remotedesktop.MaxConnections; i++ {
		if _, err := d.store.Open(context.Background(), remotedesktop.Connection{Account: iam.ManagementAccount, InstanceID: "i-0123456789abcdef0"}, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if code, m := check(h); code != 400 || m["errorCode"] != "ServiceQuotaExceededException" {
		t.Errorf("at the quota: %d %v", code, m)
	}
}

// A connection takes its credentials from the browser's first message (never the URL), carries guacd's
// instructions, is active while open and in the history once closed — without its password.
func TestRemoteDesktop_Connection(t *testing.T) {
	d, h, sess := rdFixture(t, nil, "windows-server-2022", true)
	srv := httptest.NewServer(h)
	defer srv.Close()
	cfg, _ := websocket.NewConfig("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/vms/apps/win/remote-desktop", srv.URL)
	cfg.Protocol = []string{"guacamole"}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = websocket.Message.Send(ws, `{"username":"Administrator","password":"Pa55-w0rd!","width":1280,"height":720}`)
	var got string
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := websocket.Message.Receive(ws, &got); err != nil || !strings.Contains(got, "4.sync,1.1;") {
		t.Fatalf("the browser got %q %v", got, err)
	}
	if sess.creds.Username != "Administrator" || sess.creds.Password != "Pa55-w0rd!" {
		t.Fatalf("credentials passed: %+v", sess.creds)
	}
	ctx := context.Background()
	if a, _ := d.store.Active(ctx, iam.ManagementAccount); len(a) != 1 || a[0].Username != "Administrator" || a[0].InstanceID != "i-0123456789abcdef0" {
		t.Fatalf("active: %+v", a)
	}
	ws.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hist, _ := d.store.History(ctx, iam.ManagementAccount)
		if len(hist) == 1 {
			if hist[0].Status != remotedesktop.StatusDisconnected {
				t.Fatalf("history: %+v", hist)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the closed connection is not in the history")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cms, _ := d.store.CS.CoreV1().ConfigMaps(rdTestNS).List(ctx, metav1.ListOptions{})
	leases, _ := d.store.CS.CoordinationV1().Leases(rdTestNS).List(ctx, metav1.ListOptions{})
	b, _ := json.Marshal([]any{cms, leases})
	if strings.Contains(string(b), "Pa55-w0rd!") {
		t.Fatal("the password was recorded")
	}
}

// A connection with no credentials is refused in the protocol, telling the browser why.
func TestRemoteDesktop_ConnectionNeedsCredentials(t *testing.T) {
	_, h, _ := rdFixture(t, nil, "windows-server-2022", true)
	srv := httptest.NewServer(h)
	defer srv.Close()
	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/vms/apps/win/remote-desktop", "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = websocket.Message.Send(ws, `{"password":"x"}`)
	var got string
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = websocket.Message.Receive(ws, &got)
	if !strings.HasPrefix(got, "5.error,") || !strings.Contains(got, "user name and password") {
		t.Fatalf("got %q", got)
	}
}

// ListConnections, GetConnection and CancelConnection see the session's account's connections alone.
func TestRemoteDesktop_ConnectionsAreTheAccounts(t *testing.T) {
	d, h, _ := rdFixture(t, nil, "windows-server-2022", true)
	ctx := context.Background()
	const other = "444455556666"
	mine, _ := d.store.Open(ctx, remotedesktop.Connection{Account: iam.ManagementAccount, InstanceID: "i-0123456789abcdef0"}, "x")
	theirs, _ := d.store.Open(ctx, remotedesktop.Connection{Account: other, InstanceID: "i-0fedcba9876543210"}, "x")
	var list struct{ Active, History []remotedesktop.Connection }
	_ = json.Unmarshal(serve(h, httptest.NewRequest(http.MethodGet, "/api/remote-desktop/connections", nil)).Body.Bytes(), &list)
	if len(list.Active) != 1 || list.Active[0].ConnectionID != mine.Connection().ConnectionID {
		t.Fatalf("list: %+v", list)
	}
	if rec := serve(h, httptest.NewRequest(http.MethodGet, "/api/remote-desktop/connections/"+mine.Connection().ConnectionID, nil)); rec.Code != 200 {
		t.Errorf("get mine: %d", rec.Code)
	}
	if rec := serve(h, httptest.NewRequest(http.MethodGet, "/api/remote-desktop/connections/"+theirs.Connection().ConnectionID, nil)); rec.Code != 404 {
		t.Errorf("get another account's: %d", rec.Code)
	}
	if rec := serve(h, httptest.NewRequest(http.MethodPost, "/api/remote-desktop/connections/"+theirs.Connection().ConnectionID+"/cancel", nil)); rec.Code != 404 {
		t.Errorf("cancel another account's: %d", rec.Code)
	}
	if rec := serve(h, httptest.NewRequest(http.MethodPost, "/api/remote-desktop/connections/"+mine.Connection().ConnectionID+"/cancel", nil)); rec.Code != 200 {
		t.Errorf("cancel mine: %d %s", rec.Code, rec.Body.String())
	}
}
