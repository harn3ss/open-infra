package vmconsole

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/websocket"
	"k8s.io/client-go/rest"
)

// DialSubresource opens a stream to a websocket subresource of VM ns/name's VirtualMachineInstance
// ("console" for its serial port, "portforward/<port>/tcp" for a port of the guest) with cfg's identity:
// KubeVirt's plain.kubevirt.io stream, both ways.
func DialSubresource(cfg *rest.Config, ns, name, subresource string) (io.ReadWriteCloser, error) {
	if cfg == nil {
		return nil, errors.New("no cluster client configured")
	}
	tc, err := rest.TLSConfigFor(cfg)
	if err != nil {
		return nil, err
	}
	if tc == nil {
		tc = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	host := strings.TrimSuffix(cfg.Host, "/")
	if !strings.HasPrefix(host, "https://") {
		host = "https://" + strings.TrimPrefix(host, "http://")
	}
	u := "wss://" + strings.TrimPrefix(host, "https://") +
		"/apis/subresources.kubevirt.io/v1/namespaces/" + ns + "/virtualmachineinstances/" + name + "/" + subresource
	wc, err := websocket.NewConfig(u, host)
	if err != nil {
		return nil, err
	}
	wc.Protocol = []string{"plain.kubevirt.io"}
	wc.TlsConfig = tc
	wc.Header = http.Header{}
	if tok := bearer(cfg); tok != "" {
		wc.Header.Set("Authorization", "Bearer "+tok)
	}
	c, err := websocket.DialConfig(wc)
	if err != nil {
		return nil, err
	}
	c.PayloadType = websocket.BinaryFrame
	return c, nil
}

// bearer is cfg's token, read from its file on each dial when it has one (a projected ServiceAccount
// token rotates).
func bearer(cfg *rest.Config) string {
	if cfg.BearerTokenFile != "" {
		if b, err := os.ReadFile(cfg.BearerTokenFile); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return cfg.BearerToken
}
