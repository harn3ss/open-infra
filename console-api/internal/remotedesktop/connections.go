// Package remotedesktop is Fleet Manager's Remote Desktop (AWS Systems Manager GUI Connect): RDP
// connections to Windows Server instances from the console, in the browser, as AWS runs them. A
// connection reaches the instance's Remote Desktop service (port 3389) through the platform, not the
// instance's network, so no security group has to allow 3389 (as Fleet Manager reaches it through
// Session Manager). guacd, the remote desktop proxy, speaks RDP to the instance and the Guacamole
// protocol to the browser.
//
// AWS's limits hold: a connection ends after 60 minutes unless renewed (Renew session), after 10 minutes
// without input, and an account and Region has at most 5 active connections.
//
// Connections are recorded in the console's namespace, so every console replica sees them: an active
// connection holds a Lease (remote-desktop-<connection id>) renewed by the replica that runs it, which
// lapses if that replica dies; an ended one is appended to its account's history ConfigMap
// (remote-desktop-history-<account>), newest first, the last HistoryLimit kept. Callers decide
// authorization first (the IAM actions); these functions only record and read.
package remotedesktop

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// AWS's limits on a Remote Desktop connection.
const (
	MaxDuration    = 60 * time.Minute
	IdleTimeout    = 10 * time.Minute
	MaxConnections = 5 // active connections per account and Region (AWS's default quota)
	HistoryLimit   = 200
)

// Statuses of a connection.
const (
	StatusActive            = "Active"
	StatusDisconnected      = "Disconnected"
	StatusTimeLimitExceeded = "Time Limit Exceeded"
	StatusIdleTimeout       = "Idle Timeout"
	StatusTerminated        = "Terminated"
	StatusFailed            = "Failed"
)

// QuotaMessage is the answer to a connection over the account's quota.
var QuotaMessage = fmt.Sprintf("You have reached the maximum of %d active Remote Desktop connections for this account and Region. "+
	"End a connection, or wait for one to end, and try again.", MaxConnections)

// ErrQuota: the account has its MaxConnections active connections.
var ErrQuota = errors.New("remote desktop connection quota reached")

// ErrNotFound: no active connection has that id in the account.
var ErrNotFound = errors.New("no such active connection")

// Connection is one Remote Desktop connection.
type Connection struct {
	ConnectionID string     `json:"connectionId"`
	Account      string     `json:"account"`
	InstanceID   string     `json:"instanceId"`
	Instance     string     `json:"instance"`  // the instance's name
	Namespace    string     `json:"namespace"` // where the instance's record is, for the console's links
	Principal    string     `json:"principal"` // the IAM principal that connected
	Username     string     `json:"username"`  // the Windows user it signed in as
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"startedAt"`
	ExpiresAt    time.Time  `json:"expiresAt,omitzero"`
	EndedAt      *time.Time `json:"endedAt,omitempty"`
	Reason       string     `json:"reason,omitempty"`
}

const (
	leaseSeconds   = 30
	renewEvery     = 10 * time.Second
	annConnection  = "openinfra.dev/remote-desktop-connection"
	annCancel      = "openinfra.dev/remote-desktop-cancel"
	labelComponent = "app.kubernetes.io/component"
	labelAccount   = "openinfra.dev/account-id"
	component      = "remote-desktop"
)

var (
	idRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	accountRe = regexp.MustCompile(`^[0-9]{12}$`)
)

// ValidID reports whether id is a connection id's shape.
func ValidID(id string) bool { return idRe.MatchString(id) }

func leaseName(id string) string { return "remote-desktop-" + id }

// HistoryConfigMap is the ConfigMap holding account's ended connections.
func HistoryConfigMap(account string) string { return "remote-desktop-history-" + account }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Store records connections in namespace NS.
type Store struct {
	CS  kubernetes.Interface
	NS  string
	Now func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) held(l *coordv1.Lease) bool {
	if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity == "" || l.Spec.RenewTime == nil {
		return false
	}
	d := leaseSeconds
	if l.Spec.LeaseDurationSeconds != nil {
		d = int(*l.Spec.LeaseDurationSeconds)
	}
	return s.now().Before(l.Spec.RenewTime.Add(time.Duration(d) * time.Second))
}

func connectionOf(l *coordv1.Lease) (Connection, bool) {
	var c Connection
	if err := json.Unmarshal([]byte(l.Annotations[annConnection]), &c); err != nil || c.ConnectionID == "" {
		return Connection{}, false
	}
	return c, true
}

func (s *Store) leases(ctx context.Context, account string) ([]coordv1.Lease, error) {
	sel := labelComponent + "=" + component
	if account != "" {
		sel += "," + labelAccount + "=" + account
	}
	l, err := s.CS.CoordinationV1().Leases(s.NS).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	return l.Items, nil
}

// Active is account's active connections, newest first.
func (s *Store) Active(ctx context.Context, account string) ([]Connection, error) {
	if !accountRe.MatchString(account) {
		return nil, fmt.Errorf("invalid account %q", account)
	}
	ls, err := s.leases(ctx, account)
	if err != nil {
		return nil, err
	}
	var out []Connection
	for i := range ls {
		if c, ok := connectionOf(&ls[i]); ok && s.held(&ls[i]) && c.Account == account {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// History is account's ended connections, newest first.
func (s *Store) History(ctx context.Context, account string) ([]Connection, error) {
	if !accountRe.MatchString(account) {
		return nil, fmt.Errorf("invalid account %q", account)
	}
	cm, err := s.CS.CoreV1().ConfigMaps(s.NS).Get(ctx, HistoryConfigMap(account), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Connection
	if v := cm.Data["connections"]; v != "" {
		if err := json.Unmarshal([]byte(v), &out); err != nil {
			return nil, fmt.Errorf("history of %s: %w", account, err)
		}
	}
	return out, nil
}

// Cancel ends account's active connection id (CancelConnection): the replica that runs it sees the
// request at its next renewal and closes it.
func (s *Store) Cancel(ctx context.Context, account, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		l, err := s.CS.CoordinationV1().Leases(s.NS).Get(ctx, leaseName(id), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		c, ok := connectionOf(l)
		if !ok || c.Account != account || !s.held(l) {
			return ErrNotFound
		}
		l.Annotations[annCancel] = "true"
		_, err = s.CS.CoordinationV1().Leases(s.NS).Update(ctx, l, metav1.UpdateOptions{})
		return err
	})
}

// Handle is an open connection's record, held by the replica that runs it.
type Handle struct {
	s       *Store
	conn    Connection
	holder  string
	stop    context.CancelFunc
	ended   chan string // the reason the record says it must end (cancelled, lost)
	renewed chan time.Time
}

// Connection is the record as opened.
func (h *Handle) Connection() Connection { return h.conn }

// Ended fires with a status when the connection must end from outside: CancelConnection (Terminated), or
// its record lost.
func (h *Handle) Ended() <-chan string { return h.ended }

// Open records a new active connection for c (its account, instance, principal and user), held by holder
// (this replica), or answers ErrQuota. Its lease is renewed until Close.
func (s *Store) Open(ctx context.Context, c Connection, holder string) (*Handle, error) {
	if !accountRe.MatchString(c.Account) {
		return nil, fmt.Errorf("invalid account %q", c.Account)
	}
	active, err := s.Active(ctx, c.Account)
	if err != nil {
		return nil, err
	}
	if len(active) >= MaxConnections {
		return nil, ErrQuota
	}
	now := s.now()
	c.ConnectionID, c.Status, c.StartedAt, c.ExpiresAt = newID(), StatusActive, now.UTC(), now.Add(MaxDuration).UTC()
	body, _ := json.Marshal(c)
	dur := int32(leaseSeconds)
	mt := metav1.NewMicroTime(now)
	hid := holder + "/" + c.ConnectionID
	_, err = s.CS.CoordinationV1().Leases(s.NS).Create(ctx, &coordv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: leaseName(c.ConnectionID), Namespace: s.NS,
			Labels:      map[string]string{"app.kubernetes.io/part-of": "open-infra", labelComponent: component, labelAccount: c.Account},
			Annotations: map[string]string{annConnection: string(body)}},
		Spec: coordv1.LeaseSpec{HolderIdentity: &hid, LeaseDurationSeconds: &dur, AcquireTime: &mt, RenewTime: &mt},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	// Two replicas opening at once can both pass the count: the later of any over the quota gives way.
	if after, err := s.Active(ctx, c.Account); err == nil && len(after) > MaxConnections {
		sort.Slice(after, func(i, j int) bool {
			if after[i].StartedAt.Equal(after[j].StartedAt) {
				return after[i].ConnectionID < after[j].ConnectionID
			}
			return after[i].StartedAt.Before(after[j].StartedAt)
		})
		for _, a := range after[MaxConnections:] {
			if a.ConnectionID == c.ConnectionID {
				_ = s.CS.CoordinationV1().Leases(s.NS).Delete(context.WithoutCancel(ctx), leaseName(c.ConnectionID), metav1.DeleteOptions{})
				return nil, ErrQuota
			}
		}
	}
	rctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	h := &Handle{s: s, conn: c, holder: hid, stop: stop, ended: make(chan string, 1), renewed: make(chan time.Time, 1)}
	go h.renew(rctx)
	return h, nil
}

// Renew resets the connection's maximum duration from now (Renew session) and answers its new end.
func (h *Handle) Renew() time.Time {
	exp := h.s.now().Add(MaxDuration).UTC()
	select {
	case h.renewed <- exp:
	default:
		select {
		case <-h.renewed:
		default:
		}
		h.renewed <- exp
	}
	return exp
}

func (h *Handle) renew(ctx context.Context) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	leases := h.s.CS.CoordinationV1().Leases(h.s.NS)
	var expires *time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-h.renewed:
			expires = &e
			continue
		case <-t.C:
		}
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			l, err := leases.Get(ctx, leaseName(h.conn.ConnectionID), metav1.GetOptions{})
			if err != nil {
				return err
			}
			if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != h.holder {
				return apierrors.NewNotFound(coordv1.Resource("leases"), l.Name)
			}
			if l.Annotations[annCancel] == "true" {
				return errCancelled
			}
			if expires != nil {
				c := h.conn
				c.ExpiresAt = *expires
				b, _ := json.Marshal(c)
				l.Annotations[annConnection] = string(b)
			}
			rt := metav1.NewMicroTime(h.s.now())
			l.Spec.RenewTime = &rt
			_, err = leases.Update(ctx, l, metav1.UpdateOptions{})
			return err
		})
		switch {
		case err == nil:
			expires = nil
		case errors.Is(err, errCancelled):
			h.signal(StatusTerminated)
			return
		case apierrors.IsNotFound(err):
			h.signal(StatusTerminated)
			return
		}
	}
}

var errCancelled = errors.New("cancelled")

func (h *Handle) signal(status string) {
	select {
	case h.ended <- status:
	default:
	}
}

// Close ends the connection with status (and why), removing its active record and adding it to its
// account's history.
func (h *Handle) Close(status, reason string) {
	h.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leases := h.s.CS.CoordinationV1().Leases(h.s.NS)
	if l, err := leases.Get(ctx, leaseName(h.conn.ConnectionID), metav1.GetOptions{}); err == nil &&
		l.Spec.HolderIdentity != nil && *l.Spec.HolderIdentity == h.holder {
		_ = leases.Delete(ctx, l.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &l.ResourceVersion}})
	}
	c := h.conn
	end := h.s.now().UTC()
	c.Status, c.EndedAt, c.Reason, c.ExpiresAt = status, &end, reason, time.Time{}
	_ = h.s.appendHistory(ctx, c)
}

func (s *Store) appendHistory(ctx context.Context, c Connection) error {
	cms := s.CS.CoreV1().ConfigMaps(s.NS)
	name := HistoryConfigMap(c.Account)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := cms.Get(ctx, name, metav1.GetOptions{})
		create := apierrors.IsNotFound(err)
		if err != nil && !create {
			return err
		}
		var list []Connection
		if !create && cm.Data["connections"] != "" {
			_ = json.Unmarshal([]byte(cm.Data["connections"]), &list)
		}
		list = append([]Connection{c}, list...)
		if len(list) > HistoryLimit {
			list = list[:HistoryLimit]
		}
		b, _ := json.Marshal(list)
		if create {
			_, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.NS,
				Labels: map[string]string{"app.kubernetes.io/part-of": "open-infra", labelComponent: component, labelAccount: c.Account}},
				Data: map[string]string{"connections": string(b)}}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				return apierrors.NewConflict(corev1.Resource("configmaps"), name, err)
			}
			return err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data["connections"] = string(b)
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}
