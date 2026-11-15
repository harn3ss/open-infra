package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

const testShimNS = "open-infra-aws-shim"

// pipeSerial is a VM's serial port that prints a login prompt and echoes what it is sent — after the
// prompt, as a guest's console would.
type pipeSerial struct {
	r        *io.PipeReader
	w        *io.PipeWriter
	prompted chan struct{}
}

func newPipeSerial() *pipeSerial {
	r, w := io.Pipe()
	p := &pipeSerial{r: r, w: w, prompted: make(chan struct{})}
	go func() { _, _ = w.Write([]byte("ubuntu login: ")); close(p.prompted) }()
	return p
}
func (p *pipeSerial) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *pipeSerial) Write(b []byte) (int, error) {
	data := append([]byte{}, b...)
	go func() { <-p.prompted; _, _ = p.w.Write(data) }()
	return len(b), nil
}
func (p *pipeSerial) Close() error { return p.w.Close() }

func serialFixture(t *testing.T, running bool) (*serialConsole, *fake.Clientset, http.Handler) {
	t.Helper()
	cs := fake.NewSimpleClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: serialEndpointService, Namespace: testShimNS},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "192.0.2.22"}}}}})
	s := &serialConsole{cs: cs, ns: testShimNS, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		vmAccount: func(context.Context, string) string { return iam.ManagementAccount },
		dial:      func(string, string) (io.ReadWriteCloser, error) { return newPipeSerial(), nil },
		running: func(context.Context, string, string) error {
			if running {
				return nil
			}
			return vmconsole.ErrNotRunning
		},
		instanceID: func(context.Context, string, string) (string, error) { return "i-0123456789abcdef0", nil },
	}
	r := chi.NewRouter()
	r.Get("/api/ec2/serial-console-access", s.handleAccessStatus())
	r.Post("/api/ec2/serial-console-access/enable", s.handleSetAccess(true))
	r.Post("/api/ec2/serial-console-access/disable", s.handleSetAccess(false))
	r.Get("/api/vms/{namespace}/{name}/serial-console/check", s.handleCheck())
	r.Get("/api/vms/{namespace}/{name}/serial-console", s.handleTerminal())
	return s, cs, r
}

func serialServe(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

// The account's access reads off, is turned on and off, and the status carries the SSH endpoint's address.
func TestSerialConsoleAccessRoutes(t *testing.T) {
	_, _, h := serialFixture(t, true)
	var st serialAccessStatus
	_ = json.Unmarshal(serialServe(h, http.MethodGet, "/api/ec2/serial-console-access").Body.Bytes(), &st)
	if st.Enabled || st.Endpoint != "192.0.2.22" {
		t.Errorf("a new account: %+v", st)
	}
	if w := serialServe(h, http.MethodPost, "/api/ec2/serial-console-access/enable"); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(serialServe(h, http.MethodGet, "/api/ec2/serial-console-access").Body.Bytes(), &st)
	if !st.Enabled {
		t.Error("enabled account reads off")
	}
	serialServe(h, http.MethodPost, "/api/ec2/serial-console-access/disable")
	_ = json.Unmarshal(serialServe(h, http.MethodGet, "/api/ec2/serial-console-access").Body.Bytes(), &st)
	if st.Enabled {
		t.Error("disabled account reads on")
	}
}

// The check answers EC2 Instance Connect's reason a session can't open: access off, the instance not
// running, its one session open; else its instance id.
func TestSerialConsoleCheck(t *testing.T) {
	ctx := context.Background()
	check := func(h http.Handler) (int, map[string]string) {
		w := serialServe(h, http.MethodGet, "/api/vms/acct/web/serial-console/check")
		var m map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	_, cs, h := serialFixture(t, true)
	if code, m := check(h); code != 400 || m["errorCode"] != "SerialConsoleAccessDisabledException" {
		t.Errorf("access off: %d %v", code, m)
	}
	_ = serialconsole.SetEnabled(ctx, cs, testShimNS, iam.ManagementAccount, true)
	if code, m := check(h); code != 200 || m["instanceId"] != "i-0123456789abcdef0" {
		t.Errorf("ready: %d %v", code, m)
	}
	release, _ := serialconsole.Acquire(ctx, cs, testShimNS, "i-0123456789abcdef0", "aws-shim")
	if code, m := check(h); code != 400 || m["errorCode"] != "SerialConsoleSessionLimitExceededException" {
		t.Errorf("a session open at the SSH endpoint: %d %v", code, m)
	}
	release()
	_, cs2, stopped := serialFixture(t, false)
	_ = serialconsole.SetEnabled(ctx, cs2, testShimNS, iam.ManagementAccount, true)
	if code, m := check(stopped); code != 400 || m["errorCode"] != "EC2InstanceStateInvalidException" {
		t.Errorf("not running: %d %v", code, m)
	}
}

// The terminal is the VM's serial port both ways, holding the instance's one session while it is open; a
// page of another site can't open it.
func TestSerialConsoleTerminal(t *testing.T) {
	ctx := context.Background()
	_, cs, h := serialFixture(t, true)
	_ = serialconsole.SetEnabled(ctx, cs, testShimNS, iam.ManagementAccount, true)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/vms/acct/web/serial-console"
	ws, err := websocket.Dial(wsURL, "", srv.URL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	read := func() string {
		_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		var got strings.Builder
		buf := make([]byte, 256)
		for !strings.Contains(got.String(), "ubuntu login: ") || !strings.Contains(got.String(), "root") {
			n, err := ws.Read(buf)
			if err != nil {
				break
			}
			got.Write(buf[:n])
		}
		return got.String()
	}
	_, _ = ws.Write([]byte("root"))
	if out := read(); !strings.Contains(out, "ubuntu login: ") || !strings.Contains(out, "root") {
		t.Errorf("the serial console: %q", out)
	}
	if busy, _ := serialconsole.Busy(ctx, cs, testShimNS, "i-0123456789abcdef0"); !busy {
		t.Error("an open terminal does not hold the instance's session")
	}
	ws.Close()
	if _, err := websocket.Dial(wsURL, "", "https://elsewhere.example"); err == nil {
		t.Error("another site's page opened the terminal")
	}
}
