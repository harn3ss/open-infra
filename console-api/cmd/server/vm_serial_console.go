package main

// EC2 Serial Console in the console: the account's access setting (EC2's Settings → EC2 Serial Console,
// GetSerialConsoleAccessStatus / EnableSerialConsoleAccess / DisableSerialConsoleAccess) and a VM's
// "Connect → EC2 serial console" browser terminal. The route table decides the IAM action first (the
// terminal is ec2-instance-connect:SendSerialConsoleSSHPublicKey on the instance, as the AWS console's is);
// the setting and the instance's one session are internal/serialconsole's, shared with the aws-shim's SSH
// endpoint, so a session there and one here are the same instance's one session.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

// serialEndpointService is the aws-shim's SSH endpoint Service, whose address the console shows.
const serialEndpointService = "aws-shim-serial-console"

type serialConsole struct {
	cs     kubernetes.Interface
	cfg    *rest.Config
	ns     string // the aws-shim's namespace: the setting, the sessions, the SSH endpoint
	z      *consoleAuthz
	logger *slog.Logger
	// vmAccount is the account a VM namespace is in; dial connects to a VM's serial console; running
	// reports whether a VM runs; instanceID is a VM's i- id. nil: the cluster's.
	vmAccount  func(ctx context.Context, ns string) string
	dial       func(ns, vm string) (io.ReadWriteCloser, error)
	running    func(ctx context.Context, ns, vm string) error
	instanceID func(ctx context.Context, ns, vm string) (string, error)
}

func newSerialConsole(cs kubernetes.Interface, cfg *rest.Config, ns string, z *consoleAuthz, logger *slog.Logger) *serialConsole {
	s := &serialConsole{cs: cs, cfg: cfg, ns: ns, z: z, logger: logger}
	s.vmAccount = z.namespaceAccount
	s.dial = func(vmNS, vm string) (io.ReadWriteCloser, error) { return serialconsole.Dial(cfg, vmNS, vm) }
	s.running = func(ctx context.Context, vmNS, vm string) error { return vmconsole.VMIRunning(ctx, cs, vmNS, vm) }
	s.instanceID = func(ctx context.Context, vmNS, vm string) (string, error) {
		raw, err := cs.CoreV1().RESTClient().Get().AbsPath("/apis/openinfra.dev/v1/namespaces/" + vmNS + "/virtualmachines/" + vm).DoRaw(ctx)
		if err != nil {
			return "", err
		}
		var c struct {
			Status struct {
				InstanceID string `json:"instanceId"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &c); err != nil || c.Status.InstanceID == "" {
			return "", errors.New("the instance has no id yet")
		}
		return c.Status.InstanceID, nil
	}
	return s
}

type serialAccessStatus struct {
	Enabled bool `json:"serialConsoleAccessEnabled"`
	// Endpoint is the SSH endpoint's address, for `ssh <instance id>.port0@<endpoint>` (empty while it has none).
	Endpoint string `json:"endpoint,omitempty"`
}

func awsError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "errorCode": code})
}

// GET /api/ec2/serial-console-access (ec2:GetSerialConsoleAccessStatus): the session's account's setting.
func (s *serialConsole) handleAccessStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		on, err := serialconsole.Enabled(r.Context(), s.cs, s.ns, callerAccount(r))
		if err != nil {
			s.logger.Warn("serial console access status", "err", err)
			awsError(w, http.StatusBadGateway, "ServiceException", "The serial console access setting could not be read; try again.")
			return
		}
		st := serialAccessStatus{Enabled: on}
		if svc, err := s.cs.CoreV1().Services(s.ns).Get(r.Context(), serialEndpointService, metav1.GetOptions{}); err == nil {
			if ing := svc.Status.LoadBalancer.Ingress; len(ing) > 0 {
				st.Endpoint = ing[0].IP
				if ing[0].Hostname != "" {
					st.Endpoint = ing[0].Hostname
				}
			}
		}
		writeJSON(w, http.StatusOK, st)
	}
}

// POST /api/ec2/serial-console-access/{enable|disable} (ec2:EnableSerialConsoleAccess /
// ec2:DisableSerialConsoleAccess): turn the session's account's access on or off.
func (s *serialConsole) handleSetAccess(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := serialconsole.SetEnabled(r.Context(), s.cs, s.ns, callerAccount(r), on); err != nil {
			s.logger.Warn("serial console access", "on", on, "err", err)
			awsError(w, http.StatusBadGateway, "ServiceException", "The serial console access setting could not be changed; try again.")
			return
		}
		writeJSON(w, http.StatusOK, serialAccessStatus{Enabled: on})
	}
}

// ready is why VM ns/name can't open a session now (EC2 Instance Connect's error code and message), or its
// instance id.
func (s *serialConsole) ready(ctx context.Context, ns, name string) (id, code, msg string) {
	on, err := serialconsole.Enabled(ctx, s.cs, s.ns, s.vmAccount(ctx, ns))
	if err != nil {
		return "", "ServiceException", "The serial console access setting could not be read; try again."
	}
	if !on {
		return "", "SerialConsoleAccessDisabledException",
			"EC2 serial console access is not allowed for this account. Allow it under Manage access."
	}
	if err := s.running(ctx, ns, name); err != nil {
		if errors.Is(err, vmconsole.ErrNotRunning) {
			return "", "EC2InstanceStateInvalidException", "The instance isn't running. Start it, then connect to its serial console."
		}
		return "", "ServiceException", "The instance's state could not be read; try again."
	}
	id, err = s.instanceID(ctx, ns, name)
	if err != nil {
		return "", "EC2InstanceNotFoundException", "The instance has no instance ID yet; try again in a moment."
	}
	busy, err := serialconsole.Busy(ctx, s.cs, s.ns, id)
	if err != nil {
		return "", "ServiceException", "The serial console session could not be checked; try again."
	}
	if busy {
		return "", "SerialConsoleSessionLimitExceededException", serialconsole.SessionLimitMessage
	}
	return id, "", ""
}

// GET /api/vms/{namespace}/{name}/serial-console/check: whether a session can open now, answered before
// the terminal connects (a browser can't read why a websocket was refused).
func (s *serialConsole) handleCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, code, msg := s.ready(r.Context(), chi.URLParam(r, "namespace"), chi.URLParam(r, "name"))
		if code != "" {
			awsError(w, http.StatusBadRequest, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"instanceId": id})
	}
}

// GET /api/vms/{namespace}/{name}/serial-console: the browser terminal, a websocket of the VM's serial
// port, both ways, while it holds the instance's one session.
func (s *serialConsole) handleTerminal() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		srv := websocket.Server{
			Handshake: func(cfg *websocket.Config, req *http.Request) error { return sameOrigin(req) },
			Handler: func(ws *websocket.Conn) {
				defer ws.Close()
				ws.PayloadType = websocket.BinaryFrame
				say := func(msg string) { _, _ = ws.Write([]byte("\r\n" + msg + "\r\n")) }
				ctx := r.Context()
				id, code, msg := s.ready(ctx, ns, name)
				if code != "" {
					say(msg)
					return
				}
				release, err := serialconsole.Acquire(ctx, s.cs, s.ns, id, "console")
				if errors.Is(err, serialconsole.ErrSessionLimit) {
					say(serialconsole.SessionLimitMessage)
					return
				}
				if err != nil {
					s.logger.Warn("serial console session", "instance", id, "err", err)
					say("The serial console session could not be opened; try again.")
					return
				}
				defer release()
				console, err := s.dial(ns, name)
				if err != nil {
					s.logger.Warn("serial console dial", "instance", id, "err", err)
					say("The instance's serial console could not be reached; try again.")
					return
				}
				defer console.Close()
				s.logger.Info("serial console session opened", "instance", id, "via", "console")
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(console, ws); done <- struct{}{} }()
				go func() { _, _ = io.Copy(ws, console); done <- struct{}{} }()
				<-done
				s.logger.Info("serial console session closed", "instance", id, "via", "console")
			},
		}
		srv.ServeHTTP(w, r)
	}
}

// sameOrigin refuses a websocket opened by another site's page (the session cookie would ride along).
func sameOrigin(r *http.Request) error {
	o := r.Header.Get("Origin")
	if o == "" {
		return nil
	}
	u, err := url.Parse(o)
	if err != nil || u.Host != r.Host {
		return errors.New("cross-origin websocket refused")
	}
	return nil
}
