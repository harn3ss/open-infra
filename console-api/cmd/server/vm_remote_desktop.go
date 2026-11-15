package main

// Fleet Manager Remote Desktop in the console (AWS Systems Manager GUI Connect): RDP to a Windows
// Server instance in the browser. Connecting is ssm-guiconnect:StartConnection, and ssm:StartSession on
// the instance and on the AWS-StartPortForwardingSession document, as on AWS; the connections list is
// ssm-guiconnect:ListConnections, one connection ssm-guiconnect:GetConnection, ending one
// ssm-guiconnect:CancelConnection. internal/remotedesktop runs the connections (guacd, the tunnel to
// the instance, AWS's limits) and records them; this file is the routes.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/websocket"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/guac"
	"github.com/harn3ss/open-infra/console-api/internal/remotedesktop"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

// portForwardDocument is the Session Manager document Fleet Manager's Remote Desktop starts its session
// with; ssm:StartSession is asked of it as well as of the instance.
const portForwardDocument = "AWS-StartPortForwardingSession"

func portForwardDocumentARN() string {
	return "arn:aws:ssm:" + awsaction.DefaultRegion + "::document/" + portForwardDocument
}

type remoteDesktop struct {
	z      *consoleAuthz
	store  *remotedesktop.Store
	gw     *remotedesktop.Gateway
	holder string
	logger *slog.Logger
	// vmAccount is the account a VM namespace is in; instance reads a VM's id and OS; running reports
	// whether it runs. nil: the cluster's.
	vmAccount func(ctx context.Context, ns string) string
	instance  func(ctx context.Context, ns, vm string) (rdInstance, error)
	running   func(ctx context.Context, ns, vm string) error
	// connect starts a connection (the gateway's, by default).
	connect func(ctx context.Context, ns, vm string, cr remotedesktop.Credentials, size guac.Size, tz string) (rdSession, error)
}

type rdInstance struct{ ID, OS string }

type rdSession interface {
	Relay(ctx context.Context, b remotedesktop.Browser, h *remotedesktop.Handle, o remotedesktop.RelayOptions) (string, string)
}

func newRemoteDesktop(cs kubernetes.Interface, cfg *rest.Config, z *consoleAuthz, logger *slog.Logger) *remoteDesktop {
	ns := getenv("POD_NAMESPACE", "open-infra-console")
	holder := getenv("POD_NAME", "")
	if holder == "" {
		holder, _ = os.Hostname()
	}
	lo, _ := strconv.Atoi(getenv("REMOTE_DESKTOP_TUNNEL_PORT_MIN", "40000"))
	hi, _ := strconv.Atoi(getenv("REMOTE_DESKTOP_TUNNEL_PORT_MAX", "40099"))
	gwHost := getenv("REMOTE_DESKTOP_GATEWAY", "remote-desktop-gateway-pods."+ns+".svc.cluster.local")
	gwName := getenv("REMOTE_DESKTOP_GATEWAY_TLS_NAME", "remote-desktop-gateway."+ns+".svc")
	caFile := getenv("REMOTE_DESKTOP_CA_FILE", "/etc/remote-desktop-ca/ca.crt")
	gw := &remotedesktop.Gateway{
		Guacd: func(ctx context.Context) ([]string, error) {
			ips, err := net.DefaultResolver.LookupHost(ctx, gwHost)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(ips))
			for _, ip := range ips {
				out = append(out, net.JoinHostPort(ip, "4822"))
			}
			return out, nil
		},
		TLS: func() (*tls.Config, error) {
			pem, err := os.ReadFile(caFile) // read on each connection: the bundle renews
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("no CA certificate in " + caFile)
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: gwName}, nil
		},
		DialVM: func(_ context.Context, vmNS, vm string, port int) (io.ReadWriteCloser, error) {
			return vmconsole.DialSubresource(cfg, vmNS, vm, "portforward/"+strconv.Itoa(port)+"/tcp")
		},
		ListenIP: getenv("POD_IP", "127.0.0.1"),
		PortMin:  lo, PortMax: hi,
		Logger: logger,
	}
	rd := &remoteDesktop{z: z, store: &remotedesktop.Store{CS: cs, NS: ns}, gw: gw, holder: holder, logger: logger}
	rd.vmAccount = z.namespaceAccount
	rd.running = func(ctx context.Context, vmNS, vm string) error { return vmconsole.VMIRunning(ctx, cs, vmNS, vm) }
	rd.instance = func(ctx context.Context, vmNS, vm string) (rdInstance, error) {
		raw, err := cs.CoreV1().RESTClient().Get().AbsPath("/apis/openinfra.dev/v1/namespaces/" + vmNS + "/virtualmachines/" + vm).DoRaw(ctx)
		if err != nil {
			return rdInstance{}, err
		}
		var c struct {
			Spec struct {
				OS string `json:"os"`
			} `json:"spec"`
			Status struct {
				InstanceID string `json:"instanceId"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return rdInstance{}, err
		}
		return rdInstance{ID: c.Status.InstanceID, OS: c.Spec.OS}, nil
	}
	rd.connect = func(ctx context.Context, vmNS, vm string, cr remotedesktop.Credentials, size guac.Size, tz string) (rdSession, error) {
		return gw.Connect(ctx, vmNS, vm, cr, size, tz)
	}
	return rd
}

// startSession asks ssm:StartSession of the instance and of the port-forwarding document, as Fleet
// Manager's StartConnection does on AWS, writing the denial.
func (d *remoteDesktop) startSession(w http.ResponseWriter, r *http.Request) bool {
	return d.z.require(w, r, "ssm:StartSession", d.z.kindARN("VirtualMachine")(r)) &&
		d.z.require(w, r, "ssm:StartSession", portForwardDocumentARN())
}

// ready is why VM ns/name can't be connected to now (an error code and message), or its instance.
func (d *remoteDesktop) ready(ctx context.Context, ns, name string) (rdInstance, string, string) {
	inst, err := d.instance(ctx, ns, name)
	if err != nil || inst.ID == "" {
		return inst, "InvalidInstanceId", "The instance wasn't found, or has no instance ID yet."
	}
	if !strings.HasPrefix(inst.OS, "windows") {
		return inst, "ValidationException", "Remote Desktop connects to Windows Server instances. Connect to this instance with SSH or the EC2 serial console."
	}
	if err := d.running(ctx, ns, name); err != nil {
		if errors.Is(err, vmconsole.ErrNotRunning) {
			return inst, "TargetNotConnected", inst.ID + " is not connected. Start the instance, then connect with Remote Desktop."
		}
		return inst, "InternalServerException", "The instance's state could not be read; try again."
	}
	active, err := d.store.Active(ctx, d.vmAccount(ctx, ns))
	if err != nil {
		return inst, "InternalServerException", "The account's connections could not be read; try again."
	}
	if len(active) >= remotedesktop.MaxConnections {
		return inst, "ServiceQuotaExceededException", remotedesktop.QuotaMessage
	}
	return inst, "", ""
}

// GET /api/vms/{namespace}/{name}/remote-desktop/check: whether a connection can start now, answered
// before the browser opens it (a browser can't read why a websocket was refused).
func (d *remoteDesktop) handleCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.startSession(w, r) {
			return
		}
		inst, code, msg := d.ready(r.Context(), chi.URLParam(r, "namespace"), chi.URLParam(r, "name"))
		if code != "" {
			awsError(w, http.StatusBadRequest, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instanceId": inst.ID,
			"maxDurationMinutes": int(remotedesktop.MaxDuration / time.Minute), "idleTimeoutMinutes": int(remotedesktop.IdleTimeout / time.Minute)})
	}
}

// rdStart is the browser's first message on the connection: the Windows credentials (never in the
// URL) and its display.
type rdStart struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	DPI      int    `json:"dpi"`
	Timezone string `json:"timezone"`
}

func (s rdStart) size() guac.Size {
	clamp := func(v, lo, hi, def int) int {
		if v <= 0 {
			return def
		}
		return max(lo, min(hi, v))
	}
	return guac.Size{Width: clamp(s.Width, 640, 4096, 1366), Height: clamp(s.Height, 480, 2160, 768), DPI: clamp(s.DPI, 72, 288, 96)}
}

type wsBrowser struct{ ws *websocket.Conn }

func (b wsBrowser) Send(m string) error { return websocket.Message.Send(b.ws, m) }
func (b wsBrowser) Receive() (string, error) {
	var m string
	err := websocket.Message.Receive(b.ws, &m)
	return m, err
}
func (b wsBrowser) Close() error { return b.ws.Close() }

// GET /api/vms/{namespace}/{name}/remote-desktop: the connection, a websocket carrying the Guacamole
// protocol between the browser and guacd. The browser sends its credentials and display first.
func (d *remoteDesktop) handleConnect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.startSession(w, r) {
			return
		}
		ns, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
		principal := ""
		if c, ok := claimsFrom(r); ok {
			principal = d.z.principal(c).ARN()
		}
		srv := websocket.Server{
			Handshake: func(cfg *websocket.Config, req *http.Request) error {
				if err := sameOrigin(req); err != nil {
					return err
				}
				for _, p := range cfg.Protocol {
					if p == "guacamole" {
						cfg.Protocol = []string{"guacamole"}
						return nil
					}
				}
				cfg.Protocol = nil
				return nil
			},
			Handler: func(ws *websocket.Conn) {
				defer ws.Close()
				ws.MaxPayloadBytes = 1 << 20
				ctx := r.Context()
				fail := func(msg string, code int) {
					_ = websocket.Message.Send(ws, guac.Error(msg, code).String())
				}
				_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
				var start rdStart
				var first string
				if err := websocket.Message.Receive(ws, &first); err != nil || json.Unmarshal([]byte(first), &start) != nil || start.Username == "" {
					fail("Enter the user name and password of a Windows account on the instance.", guac.StatusClientBadRequest)
					return
				}
				_ = ws.SetReadDeadline(time.Time{})
				inst, code, msg := d.ready(ctx, ns, name)
				if code != "" {
					status := guac.StatusClientForbidden
					if code == "ServiceQuotaExceededException" {
						status = guac.StatusClientTooMany
					}
					fail(msg, status)
					return
				}
				acct := d.vmAccount(ctx, ns)
				h, err := d.store.Open(ctx, remotedesktop.Connection{Account: acct, InstanceID: inst.ID, Instance: name, Namespace: ns,
					Principal: principal, Username: start.Username}, d.holder)
				if errors.Is(err, remotedesktop.ErrQuota) {
					fail(remotedesktop.QuotaMessage, guac.StatusClientTooMany)
					return
				}
				if err != nil {
					d.logger.Warn("remote desktop: record the connection", "instance", inst.ID, "err", err)
					fail("The connection could not be started; try again.", guac.StatusServerError)
					return
				}
				id := h.Connection().ConnectionID
				sess, err := d.connect(ctx, ns, name, remotedesktop.Credentials{Username: start.Username, Password: start.Password, Domain: start.Domain},
					start.size(), start.Timezone)
				start.Password = ""
				if err != nil {
					d.logger.Warn("remote desktop: connect", "connection", id, "instance", inst.ID, "err", err)
					why, status := "The remote desktop gateway could not be reached; try again.", guac.StatusUpstreamUnavailable
					if errors.Is(err, remotedesktop.ErrUnreachable) {
						why, status = "The instance's Remote Desktop service didn't answer. Check that the instance has finished starting and that Remote Desktop is turned on (port 3389).", guac.StatusUpstreamNotFound
					}
					h.Close(remotedesktop.StatusFailed, why)
					fail(why, status)
					return
				}
				d.logger.Info("remote desktop connection started", "connection", id, "instance", inst.ID, "principal", principal)
				status, reason := sess.Relay(ctx, wsBrowser{ws}, h, remotedesktop.RelayOptions{})
				h.Close(status, reason)
				d.logger.Info("remote desktop connection ended", "connection", id, "instance", inst.ID, "status", status, "reason", reason)
			},
		}
		srv.ServeHTTP(w, r)
	}
}

// GET /api/remote-desktop/connections (ssm-guiconnect:ListConnections): the session's account's active
// connections and connection history.
func (d *remoteDesktop) handleList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acct := callerAccount(r)
		active, err := d.store.Active(r.Context(), acct)
		if err != nil {
			d.logger.Warn("remote desktop: list active", "err", err)
			awsError(w, http.StatusBadGateway, "InternalServerException", "The connections could not be read; try again.")
			return
		}
		hist, err := d.store.History(r.Context(), acct)
		if err != nil {
			d.logger.Warn("remote desktop: list history", "err", err)
			awsError(w, http.StatusBadGateway, "InternalServerException", "The connection history could not be read; try again.")
			return
		}
		if active == nil {
			active = []remotedesktop.Connection{}
		}
		if hist == nil {
			hist = []remotedesktop.Connection{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": active, "history": hist})
	}
}

// GET /api/remote-desktop/connections/{id} (ssm-guiconnect:GetConnection): one of the session's
// account's connections, active or ended.
func (d *remoteDesktop) handleGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, acct := chi.URLParam(r, "id"), callerAccount(r)
		if !remotedesktop.ValidID(id) {
			awsError(w, http.StatusNotFound, "ResourceNotFoundException", fmt.Sprintf("Connection %s was not found.", id))
			return
		}
		active, err := d.store.Active(r.Context(), acct)
		if err == nil {
			for _, c := range active {
				if c.ConnectionID == id {
					writeJSON(w, http.StatusOK, c)
					return
				}
			}
		}
		hist, herr := d.store.History(r.Context(), acct)
		if err != nil || herr != nil {
			awsError(w, http.StatusBadGateway, "InternalServerException", "The connection could not be read; try again.")
			return
		}
		for _, c := range hist {
			if c.ConnectionID == id {
				writeJSON(w, http.StatusOK, c)
				return
			}
		}
		awsError(w, http.StatusNotFound, "ResourceNotFoundException", fmt.Sprintf("Connection %s was not found.", id))
	}
}

// POST /api/remote-desktop/connections/{id}/cancel (ssm-guiconnect:CancelConnection): end one of the
// session's account's active connections.
func (d *remoteDesktop) handleCancel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		err := d.store.Cancel(r.Context(), callerAccount(r), id)
		if errors.Is(err, remotedesktop.ErrNotFound) {
			awsError(w, http.StatusNotFound, "ResourceNotFoundException", fmt.Sprintf("No active connection %s was found.", id))
			return
		}
		if err != nil {
			d.logger.Warn("remote desktop: cancel", "connection", id, "err", err)
			awsError(w, http.StatusBadGateway, "InternalServerException", "The connection could not be ended; try again.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"connectionId": id, "status": "Terminating"})
	}
}
