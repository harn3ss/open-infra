package main

// EC2 Instance Connect (ec2-instance-connect.*, JSON 1.1, target AWSEC2InstanceConnectService.<Op>):
// SendSerialConsoleSSHPublicKey, the first step of an EC2 Serial Console session. It pushes the caller's SSH
// public key for one instance's serial port 0, good for 60 seconds, as EC2 does; the serial console gateway
// (serial_console_gateway.go) then lets that key in as "<instance id>.port0" and connects it to the
// instance's serial console. It is decided as ec2-instance-connect:SendSerialConsoleSSHPublicKey on the
// instance, refused while the account has not allowed serial console access
// (SerialConsoleAccessDisabledException, ec2_serial_access.go) and while the instance has its one session
// open (SerialConsoleSessionLimitExceededException).

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/serialconsole"
	"github.com/harn3ss/open-infra/console-api/internal/vmconsole"
)

func init() { accountScopedServices["ec2-instance-connect"] = true }

const (
	eicContentType  = "application/x-amz-json-1.1"
	eicTargetPrefix = "AWSEC2InstanceConnectService."
	// serialKeyTTL is how long a pushed key lets its holder in, as EC2's: 60 seconds.
	serialKeyTTL = 60 * time.Second
)

// serialKey is a key pushed for an instance: who may connect with it, to which VM, until when.
type serialKey struct {
	key             ssh.PublicKey
	account, ns, vm string
	expires         time.Time
}

// serialKeys holds the keys pushed in the last minute, per instance. In memory: a key lives 60 seconds,
// and the gateway that checks it runs in this process.
type serialKeys struct {
	mu      sync.Mutex
	pending map[string][]serialKey
	now     func() time.Time
}

func newSerialKeys() *serialKeys {
	return &serialKeys{pending: map[string][]serialKey{}, now: time.Now}
}

func (s *serialKeys) push(instanceID string, k serialKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k.expires = s.now().Add(serialKeyTTL)
	s.pending[instanceID] = append(s.live(instanceID), k)
}

// match is the pushed key of instanceID that is key, while it is good.
func (s *serialKeys) match(instanceID string, key ssh.PublicKey) (serialKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.live(instanceID)
	s.pending[instanceID] = keys
	want := key.Marshal()
	for _, k := range keys {
		if string(k.key.Marshal()) == string(want) {
			return k, true
		}
	}
	return serialKey{}, false
}

// live is instanceID's keys that have not expired (s.mu held).
func (s *serialKeys) live(instanceID string) []serialKey {
	var out []serialKey
	for _, k := range s.pending[instanceID] {
		if s.now().Before(k.expires) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		delete(s.pending, instanceID)
	}
	return out
}

type eicHandler struct {
	ec2    *ec2Handler
	keys   *serialKeys
	logger *slog.Logger
	// busy reports whether an instance has its one session open; nil: internal/serialconsole's lease.
	busy func(ctx context.Context, instanceID string) (bool, error)
	// running reports whether a VM runs (vmconsole.ErrNotRunning if not); nil: its VMI, as the shim.
	running func(ctx context.Context, ns, vm string) error
}

func newEICHandler(ec2H *ec2Handler, keys *serialKeys, logger *slog.Logger) *eicHandler {
	return &eicHandler{ec2: ec2H, keys: keys, logger: logger}
}

func writeEICError(w http.ResponseWriter, code, requestID, message string) {
	w.Header().Set("Content-Type", eicContentType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "Message": message})
}

func (h *eicHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	w.Header().Set("Content-Type", eicContentType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(authStatus(r, http.StatusForbidden))
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": authCode(r, "InvalidSignatureException"),
		"Message": authMessage(r, "The request signature we calculated does not match the signature you provided.")})
}

func (h *eicHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), eicTargetPrefix)
	switch op {
	case "SendSerialConsoleSSHPublicKey":
	case "SendSSHPublicKey":
		writeEICError(w, "NotImplemented", requestID,
			"EC2 Instance Connect SendSSHPublicKey is not served here: connect with your instance's key pair, or use SendSerialConsoleSSHPublicKey for its serial console.")
		return
	default:
		writeEICError(w, "InvalidAction", requestID, "no such EC2 Instance Connect operation: "+r.Header.Get("X-Amz-Target"))
		return
	}
	var req struct {
		InstanceID   string `json:"InstanceId"`
		SSHPublicKey string `json:"SSHPublicKey"`
		SerialPort   *int   `json:"SerialPort"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeEICError(w, "InvalidArgsException", requestID, "The request body is not valid JSON.")
		return
	}
	switch {
	case req.InstanceID == "" || req.SSHPublicKey == "":
		writeEICError(w, "InvalidArgsException", requestID, "InstanceId and SSHPublicKey are required.")
		return
	case !instanceIDRe.MatchString(req.InstanceID):
		writeEICError(w, "InvalidArgsException", requestID, "Invalid instance ID: "+req.InstanceID)
		return
	case req.SerialPort != nil && *req.SerialPort != 0:
		writeEICError(w, "InvalidArgsException", requestID, "Only serial port 0 is supported.")
		return
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
	e := h.ec2
	if e == nil || e.door == nil {
		writeEICError(w, "ServiceException", requestID, "EC2 Instance Connect needs the EC2 front door, which is not configured on this shim.")
		return
	}
	if ok, reason := decide(ctx, r, e.door.authz, claims, "ec2-instance-connect:SendSerialConsoleSSHPublicKey", "Instance", req.InstanceID,
		dataPlaneOnly(ctx, r, e.door.authz, claims, "ec2-instance-connect:SendSerialConsoleSSHPublicKey", "Instance", req.InstanceID)); !ok {
		e.audit(ctx, "SendSerialConsoleSSHPublicKey", req.InstanceID, reason)
		writeEICError(w, "AccessDeniedException", requestID,
			"You are not authorized to perform ec2-instance-connect:SendSerialConsoleSSHPublicKey on this instance. "+reason)
		return
	}
	account := e.serialAccount(ctx)
	if e.door.cs == nil || e.settingsNS == "" {
		writeEICError(w, "ServiceException", requestID, "EC2 Serial Console is not configured on this endpoint.")
		return
	}
	on, err := serialconsole.Enabled(ctx, e.door.cs, e.settingsNS, account)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	if !on {
		writeEICError(w, "SerialConsoleAccessDisabledException", requestID,
			"Your account is not authorized to use the EC2 Serial Console. To authorize your account, run the EnableSerialConsoleAccess API.")
		return
	}
	all, _, err := e.instancesForCaller(ctx, claims)
	if err != nil {
		h.fail(w, requestID, err)
		return
	}
	var in *ec2Instance
	for i := range all {
		if all[i].id == req.InstanceID {
			in = &all[i]
		}
	}
	if in == nil {
		writeEICError(w, "EC2InstanceNotFoundException", requestID, "Instance not found: "+req.InstanceID)
		return
	}
	// Running is the VM's own state (its VMI), not the claim's read-back, which lags a boot by minutes.
	running := h.running
	if running == nil {
		running = func(ctx context.Context, ns, vm string) error { return vmconsole.VMIRunning(ctx, e.door.cs, ns, vm) }
	}
	if err := running(ctx, e.accountNS(ctx), in.claim.GetName()); errors.Is(err, vmconsole.ErrNotRunning) {
		writeEICError(w, "EC2InstanceStateInvalidException", requestID,
			"Unable to connect because the instance is not in a valid state. Connecting to a stopped or terminated instance is not supported. If the instance is stopped, start your instance, and try to connect again.")
		return
	} else if err != nil {
		h.fail(w, requestID, err)
		return
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHPublicKey))
	if err != nil || !serialKeyType(key) {
		writeEICError(w, "InvalidArgsException", requestID, "The SSH public key is not valid: give an OpenSSH ssh-rsa (2048 bits or more) or ssh-ed25519 key.")
		return
	}
	busy := h.busy
	if busy == nil {
		busy = func(ctx context.Context, id string) (bool, error) {
			return serialconsole.Busy(ctx, e.door.cs, e.settingsNS, id)
		}
	}
	if b, err := busy(ctx, req.InstanceID); err != nil {
		h.fail(w, requestID, err)
		return
	} else if b {
		writeEICError(w, "SerialConsoleSessionLimitExceededException", requestID, serialconsole.SessionLimitMessage)
		return
	}
	h.keys.push(req.InstanceID, serialKey{key: key, account: account, ns: e.accountNS(ctx), vm: in.claim.GetName()})
	w.Header().Set("Content-Type", eicContentType)
	w.Header().Set("x-amzn-RequestId", requestID)
	_ = json.NewEncoder(w).Encode(map[string]any{"RequestId": requestID, "Success": true})
}

// serialKeyType: the key types EC2 Instance Connect takes, an RSA key of 2048 bits or more, or ED25519.
func serialKeyType(k ssh.PublicKey) bool {
	switch k.Type() {
	case ssh.KeyAlgoED25519:
		return true
	case ssh.KeyAlgoRSA:
		if ck, ok := k.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
				return rk.N.BitLen() >= 2048
			}
		}
	}
	return false
}

func (h *eicHandler) fail(w http.ResponseWriter, requestID string, err error) {
	if h.logger != nil {
		h.logger.Warn("ec2-instance-connect: SendSerialConsoleSSHPublicKey failed", "error", err.Error())
	}
	writeEICError(w, "ServiceException", requestID, "The request could not be completed; retry.")
}
