package main

// The EC2 Serial Console's SSH endpoint (AWS's serial-console.ec2-instance-connect.<region>.aws): an SSH
// server that connects a session to an instance's serial console, as
//
//	aws ec2-instance-connect send-serial-console-ssh-public-key --instance-id i-… --serial-port 0 \
//	    --ssh-public-key file://key.pub
//	ssh -i key i-….port0@<serial console endpoint>
//
// The user is "<instance id>.port0", and the only credential it takes is a key pushed for that instance in
// the last 60 seconds (ec2_instance_connect.go), which IAM allowed, for an account that allows serial
// console access; no password is ever asked. The account's access is checked again when the session
// opens, the instance's one session is held while it runs (internal/serialconsole), and the session is the
// VM's serial port, both ways (KubeVirt's console subresource, as the shim). Its host key is kept in a
// Secret in the shim's namespace, made on first start, so its fingerprint stays the same across restarts.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
)

// serialHostKeySecret holds the gateway's host key (ssh_host_ed25519_key, OpenSSH PEM).
const serialHostKeySecret = "aws-shim-serial-console-host-key"

var serialUserRe = regexp.MustCompile(`^(i-[0-9a-f]{17})\.port0$`)

type serialGateway struct {
	keys    *serialKeys
	hostKey ssh.Signer
	logger  *slog.Logger
	// enabled reports whether an account allows serial console access; acquire holds an instance's one
	// session; dial connects to a VM's serial console.
	enabled func(ctx context.Context, account string) (bool, error)
	acquire func(ctx context.Context, instanceID string) (func(), error)
	dial    func(ns, vm string) (io.ReadWriteCloser, error)
}

// newSerialGateway is the gateway over the cluster: the account setting and the session leases in ns (the
// shim's namespace), the console reached with cfg (the shim's identity).
func newSerialGateway(ctx context.Context, cs kubernetes.Interface, cfg *rest.Config, ns string, keys *serialKeys, logger *slog.Logger) (*serialGateway, error) {
	hk, err := loadOrMakeHostKey(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	return &serialGateway{keys: keys, hostKey: hk, logger: logger,
		enabled: func(ctx context.Context, account string) (bool, error) {
			return serialconsole.Enabled(ctx, cs, ns, account)
		},
		acquire: func(ctx context.Context, id string) (func(), error) {
			return serialconsole.Acquire(ctx, cs, ns, id, "aws-shim")
		},
		dial: func(vmNS, vm string) (io.ReadWriteCloser, error) { return serialconsole.Dial(cfg, vmNS, vm) },
	}, nil
}

func loadOrMakeHostKey(ctx context.Context, cs kubernetes.Interface, ns string) (ssh.Signer, error) {
	secrets := cs.CoreV1().Secrets(ns)
	for i := 0; i < 2; i++ {
		s, err := secrets.Get(ctx, serialHostKeySecret, metav1.GetOptions{})
		if err == nil {
			return ssh.ParsePrivateKey(s.Data["ssh_host_ed25519_key"])
		}
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "aws-shim serial console")
		if err != nil {
			return nil, err
		}
		_, err = secrets.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: serialHostKeySecret, Namespace: ns,
				Labels: map[string]string{"app.kubernetes.io/part-of": "open-infra", "app.kubernetes.io/component": "serial-console"}},
			Data: map[string][]byte{"ssh_host_ed25519_key": pem.EncodeToMemory(block)},
		}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}
	return nil, errors.New("the serial console host key could not be made")
}

func (g *serialGateway) config() *ssh.ServerConfig {
	c := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			m := serialUserRe.FindStringSubmatch(meta.User())
			if m == nil {
				return nil, errors.New("the user is <instance id>.port0")
			}
			k, ok := g.keys.match(m[1], key)
			if !ok {
				return nil, errors.New("no key was pushed for this instance in the last 60 seconds")
			}
			return &ssh.Permissions{Extensions: map[string]string{"instance": m[1], "account": k.account, "ns": k.ns, "vm": k.vm}}, nil
		},
		MaxAuthTries:  3,
		ServerVersion: "SSH-2.0-OpenInfraSerialConsole",
	}
	c.AddHostKey(g.hostKey)
	return c
}

// serve accepts connections on l until it is closed.
func (g *serialGateway) serve(l net.Listener) error {
	cfg := g.config()
	for {
		nc, err := l.Accept()
		if err != nil {
			return err
		}
		go g.handle(nc, cfg)
	}
}

func (g *serialGateway) handle(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second)) // the handshake and authentication
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = nc.SetDeadline(time.Time{})
	go ssh.DiscardRequests(reqs)
	p := conn.Permissions.Extensions
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessions := 0
	for nch := range chans {
		if nch.ChannelType() != "session" || sessions > 0 {
			_ = nch.Reject(ssh.Prohibited, "one serial console session per connection")
			continue
		}
		sessions++
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go g.session(ctx, conn, ch, creqs, p)
	}
}

// session runs one session: once the client asks for a shell, the instance's serial console, until
// either side ends.
func (g *serialGateway) session(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request, p map[string]string) {
	defer conn.Close()
	defer ch.Close()
	var once sync.Once
	start := make(chan struct{})
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell":
				_ = req.Reply(true, nil)
				once.Do(func() { close(start) })
			case "pty-req", "env", "window-change":
				_ = req.Reply(true, nil)
			default: // exec, subsystem, …: a serial console runs nothing
				_ = req.Reply(false, nil)
			}
		}
	}()
	select {
	case <-start:
	case <-time.After(30 * time.Second):
		return
	}
	exit := func(code uint32, msg string) {
		if msg != "" {
			_, _ = fmt.Fprint(ch.Stderr(), msg+"\r\n")
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
	}
	instance := p["instance"]
	if on, err := g.enabled(ctx, p["account"]); err != nil || !on {
		exit(1, "Your account is not authorized to use the EC2 Serial Console.")
		return
	}
	release, err := g.acquire(ctx, instance)
	if errors.Is(err, serialconsole.ErrSessionLimit) {
		exit(1, serialconsole.SessionLimitMessage)
		return
	}
	if err != nil {
		g.warn("serial console session not opened", instance, err)
		exit(1, "The serial console session could not be opened; retry.")
		return
	}
	defer release()
	console, err := g.dial(p["ns"], p["vm"])
	if err != nil {
		g.warn("serial console not reached", instance, err)
		exit(1, "The instance's serial console could not be reached; retry.")
		return
	}
	defer console.Close()
	if g.logger != nil {
		g.logger.Info("serial console session opened", "instance", instance, "account", p["account"])
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(console, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, console); done <- struct{}{} }()
	<-done
	exit(0, "")
	if g.logger != nil {
		g.logger.Info("serial console session closed", "instance", instance, "account", p["account"])
	}
}

func (g *serialGateway) warn(msg, instance string, err error) {
	if g.logger != nil {
		g.logger.Warn(msg, "instance", instance, "error", err.Error())
	}
}
