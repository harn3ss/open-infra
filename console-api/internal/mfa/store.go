package mfa

// Where the devices live: the credential store namespace (the aws-shim's KEYS_NAMESPACE, beside the access
// keys and login profiles), never the console namespace where root's console-auth Secret is. One Secret per
// device, named for its account and name (SecretName) — so a device name is unique within an account, as
// on AWS — and labelled as a device of that account (LabelDevice, LabelAccount). An assigned device also
// carries its user's labels (LabelUser, LabelUserNamespace) and the User's UID (AnnUserUID): a device whose
// recorded UID is not the User's is no one's, so a user deleted and recreated under the same name never
// inherits the old one's device. Admission (platform/aws-shim/mfa-device-guard.yaml) holds the name prefix
// and the device label together, and keeps a device's account and assignment from being rewritten behind
// the API's back.
//
// The Secret's data is the seed (seedKey) and the device's verification state (stateKey: the last step it
// accepted, its clock drift, consecutive failures and any lockout). Who can read a seed: the aws-shim's and
// the console's ServiceAccounts (each holds Secret rights in that namespace, for the access keys) and
// cluster administrators — no IAM principal: no API answers a seed after CreateVirtualMFADevice.
//
// What a device is (name, path, created, enabled, tags) is in its annotations, read without the seed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// SecretPrefix names every device Secret; admission holds it and LabelDevice together.
	SecretPrefix = "iam-mfa-"

	LabelDevice        = "openinfra.dev/mfa-device"
	LabelAccount       = "openinfra.dev/account-id"
	LabelUser          = "openinfra.dev/iam-user"
	LabelUserNamespace = "openinfra.dev/iam-user-namespace"

	AnnName    = "openinfra.dev/mfa-device-name"
	AnnPath    = "openinfra.dev/mfa-device-path"
	AnnCreated = "openinfra.dev/mfa-created"
	AnnEnabled = "openinfra.dev/mfa-enable-date"
	AnnUserUID = "openinfra.dev/iam-user-uid"
	AnnTags    = "openinfra.dev/mfa-tags"

	seedKey  = "seed"
	stateKey = "state"

	// MaxDevicesPerUser is AWS's limit on the MFA devices assigned to one user.
	MaxDevicesPerUser = 8
	// MaxDevicesPerAccount is AWS's default quota on an account's virtual MFA devices (assigned or not).
	MaxDevicesPerAccount = 5000
	// MaxFailures wrong codes in a row lock a device for Lockout.
	MaxFailures = 5
	Lockout     = 15 * time.Minute
	// MaxTags is AWS's limit on a device's tags.
	MaxTags = 50
)

var (
	// ErrNotFound is a device that does not exist in the account (or, for a user's operation, is not
	// assigned to that user).
	ErrNotFound = errors.New("no such MFA device")
	// ErrExists is a device name already taken in the account.
	ErrExists = errors.New("an MFA device of that name already exists")
	// ErrAssigned is a device assigned to a user: it cannot be enabled again, or deleted.
	ErrAssigned = errors.New("the MFA device is assigned to a user")
	// ErrLimit is a quota: a user's MFA devices, or an account's.
	ErrLimit = errors.New("MFA device limit exceeded")
	// ErrInvalidCode is a code that does not verify.
	ErrInvalidCode = errors.New("the authentication code is not valid")
	// ErrReplayed is a valid code already used once (it is an ErrInvalidCode).
	ErrReplayed = fmt.Errorf("%w: it was already used", ErrInvalidCode)
	// ErrLocked is a device locked by repeated wrong codes (it is an ErrInvalidCode).
	ErrLocked = fmt.Errorf("%w: too many wrong codes, the device is locked for a while", ErrInvalidCode)
)

// Tag is one of a device's tags.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Device is a virtual MFA device, as its Secret's labels and annotations describe it (never its seed).
type Device struct {
	Account    string // the store account: the management account's id is iam.ManagementAccount
	Name, Path string
	Created    time.Time
	// The user it is assigned to ("" = unassigned), and when it was enabled.
	User, UserNamespace, UserUID string
	EnableDate                   time.Time
	Tags                         []Tag
}

// Assigned reports whether the device is assigned to a user.
func (d Device) Assigned() bool { return d.User != "" }

// AssignedTo reports whether the device is assigned to the user userNS/user whose object has UID uid.
func (d Device) AssignedTo(userNS, user, uid string) bool {
	return d.User != "" && d.User == user && d.UserNamespace == userNS && (d.UserUID == "" || uid == "" || d.UserUID == uid)
}

// SerialNumber is the device's ARN in an account presented as acct: arn:aws:iam::<acct>:mfa<path><name>.
func (d Device) SerialNumber(acct string) string { return SerialNumber(acct, d.Path, d.Name) }

// SerialNumber is a virtual MFA device's ARN.
func SerialNumber(acct, path, name string) string {
	if path == "" {
		path = "/"
	}
	return "arn:aws:iam::" + acct + ":mfa" + path + name
}

// ParseSerial splits a virtual MFA device's serial number (its ARN) into the account it names, its path
// and its name; ok=false for anything else (a hardware serial, another kind of ARN).
func ParseSerial(serial string) (acct, path, name string, ok bool) {
	parts := strings.SplitN(serial, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" {
		return "", "", "", false
	}
	res, found := strings.CutPrefix(parts[5], "mfa/")
	if !found || res == "" {
		return "", "", "", false
	}
	i := strings.LastIndexByte(res, '/')
	path, name = "/"+res[:i+1], res[i+1:]
	if i < 0 {
		path = "/"
	}
	if name == "" || !nameRe.MatchString(name) {
		return "", "", "", false
	}
	return parts[4], path, name, true
}

var (
	nameRe = regexp.MustCompile(`^[\w+=,.@-]+$`)
	pathRe = regexp.MustCompile(`^(/|/[\x21-\x7e]+/)$`)
)

// ValidName reports whether name is a VirtualMFADeviceName AWS accepts.
func ValidName(name string) bool {
	return len(name) >= 1 && len(name) <= 226 && nameRe.MatchString(name)
}

// ValidPath reports whether path is a Path AWS accepts.
func ValidPath(path string) bool { return len(path) <= 512 && pathRe.MatchString(path) }

// SecretName is the Secret of account's device name: readable, unique per account and case-insensitive
// name (IAM names are not distinguished by case).
func SecretName(account, name string) string {
	lower := strings.ToLower(name)
	sum := sha256.Sum256([]byte(account + "/" + lower))
	short := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, lower)
	if len(short) > 30 {
		short = short[:30]
	}
	return SecretPrefix + strings.Trim(short, "-") + "-" + hex.EncodeToString(sum[:])[:12]
}

// IsDeviceSecret reports whether a Secret's name and labels make it a device at all.
func IsDeviceSecret(name string, labels map[string]string) bool {
	return strings.HasPrefix(name, SecretPrefix) && labels[LabelDevice] == "true"
}

// validFor reports whether a Secret is account's device name: its name, label and annotations agree.
func validFor(sec *corev1.Secret, account, name string) bool {
	return sec != nil && sec.Name == SecretName(account, name) && IsDeviceSecret(sec.Name, sec.Labels) &&
		sec.Labels[LabelAccount] == account && strings.EqualFold(sec.Annotations[AnnName], name)
}

// state is a device's verification state.
type state struct {
	LastStep    int64 `json:"lastStep"`              // the last step a code was accepted for (no code at or before it is)
	Drift       int64 `json:"drift,omitempty"`       // the device's clock, in steps ahead of the server's
	Failures    int   `json:"failures,omitempty"`    // wrong codes in a row
	LockedUntil int64 `json:"lockedUntil,omitempty"` // Unix seconds; 0 = not locked
}

// Store is the credential store namespace's MFA devices.
type Store struct {
	CS kubernetes.Interface
	NS string // the credential store namespace
	// Now is the clock (nil = time.Now); tests set it.
	Now func() time.Time
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func deviceOf(sec *corev1.Secret) Device {
	ann := sec.Annotations
	d := Device{
		Account: sec.Labels[LabelAccount], Name: ann[AnnName], Path: ann[AnnPath],
		User: sec.Labels[LabelUser], UserNamespace: sec.Labels[LabelUserNamespace], UserUID: ann[AnnUserUID],
	}
	if d.Path == "" {
		d.Path = "/"
	}
	if d.User == "" || d.UserNamespace == "" {
		d.User, d.UserNamespace, d.UserUID = "", "", ""
	}
	d.Created, _ = time.Parse(time.RFC3339, ann[AnnCreated])
	if d.Created.IsZero() {
		d.Created = sec.CreationTimestamp.UTC()
	}
	if d.User != "" {
		d.EnableDate, _ = time.Parse(time.RFC3339, ann[AnnEnabled])
	}
	if raw := ann[AnnTags]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &d.Tags)
	}
	return d
}

// Create makes account's virtual MFA device name (at path, with tags) and returns it with its seed — the
// one time the seed leaves the store. ErrExists when the name is taken, ErrLimit past the account quota.
func (s Store) Create(ctx context.Context, account, name, path string, tags []Tag) (Device, []byte, error) {
	if path == "" {
		path = "/"
	}
	list, err := s.CS.CoreV1().Secrets(s.NS).List(ctx, metav1.ListOptions{LabelSelector: LabelDevice + "=true," + LabelAccount + "=" + account})
	if err != nil {
		return Device{}, nil, err
	}
	if len(list.Items) >= MaxDevicesPerAccount {
		return Device{}, nil, ErrLimit
	}
	seed, err := NewSeed()
	if err != nil {
		return Device{}, nil, err
	}
	now := s.now().UTC()
	ann := map[string]string{AnnName: name, AnnPath: path, AnnCreated: now.Format(time.RFC3339)}
	if len(tags) > 0 {
		b, _ := json.Marshal(tags)
		ann[AnnTags] = string(b)
	}
	st, _ := json.Marshal(state{})
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName(account, name), Namespace: s.NS, Annotations: ann, Labels: map[string]string{
			"app.kubernetes.io/managed-by": "open-infra-iam",
			LabelDevice:                    "true",
			LabelAccount:                   account,
		}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{seedKey: seed, stateKey: st},
	}
	if _, err := s.CS.CoreV1().Secrets(s.NS).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return Device{}, nil, ErrExists
		}
		return Device{}, nil, err
	}
	return deviceOf(sec), seed, nil
}

// read is account's device name's Secret; ErrNotFound when there is none (or a Secret of that name that
// is not this device).
func (s Store) read(ctx context.Context, account, name string) (*corev1.Secret, error) {
	sec, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, SecretName(account, name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !validFor(sec, account, name) {
		return nil, ErrNotFound
	}
	return sec, nil
}

// Get is account's device name.
func (s Store) Get(ctx context.Context, account, name string) (Device, error) {
	sec, err := s.read(ctx, account, name)
	if err != nil {
		return Device{}, err
	}
	return deviceOf(sec), nil
}

// List is account's devices, by name.
func (s Store) List(ctx context.Context, account string) ([]Device, error) {
	list, err := s.CS.CoreV1().Secrets(s.NS).List(ctx, metav1.ListOptions{LabelSelector: LabelDevice + "=true," + LabelAccount + "=" + account})
	if err != nil {
		return nil, err
	}
	var out []Device
	for i := range list.Items {
		sec := &list.Items[i]
		if d := deviceOf(sec); validFor(sec, account, d.Name) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// ForUser is the devices assigned to the user userNS/user (UID uid) in account, by enable date.
func (s Store) ForUser(ctx context.Context, account, userNS, user, uid string) ([]Device, error) {
	list, err := s.CS.CoreV1().Secrets(s.NS).List(ctx, metav1.ListOptions{LabelSelector: LabelDevice + "=true," +
		LabelAccount + "=" + account + "," + LabelUser + "=" + user + "," + LabelUserNamespace + "=" + userNS})
	if err != nil {
		return nil, err
	}
	var out []Device
	for i := range list.Items {
		sec := &list.Items[i]
		d := deviceOf(sec)
		if validFor(sec, account, d.Name) && d.AssignedTo(userNS, user, uid) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnableDate.Before(out[j].EnableDate) })
	return out, nil
}

// update applies fn to account's device name and writes it back, retrying a write conflict — so two
// verifications racing on one code cannot both accept it: the second re-reads the step the first recorded.
// fn's error is returned as is; with keep set, the Secret is written even then (a failure is recorded).
func (s Store) update(ctx context.Context, account, name string, fn func(sec *corev1.Secret, st *state) (keep bool, err error)) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		sec, err := s.read(ctx, account, name)
		if err != nil {
			return err
		}
		var st state
		if raw := sec.Data[stateKey]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &st); err != nil {
				return fmt.Errorf("MFA device %s's state is unreadable", name)
			}
		}
		keep, ferr := fn(sec, &st)
		if ferr != nil && !keep {
			return ferr
		}
		b, _ := json.Marshal(st)
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[stateKey] = b
		if _, err := s.CS.CoreV1().Secrets(s.NS).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				lastErr = err
				continue
			}
			return err
		}
		return ferr
	}
	return lastErr
}

// verifyCodes checks one code (code2 == "") or two consecutive codes against a device's seed and state,
// recording the result: the accepted step (and, for a resync, the drift), or a failure — and a lockout
// after MaxFailures in a row. It returns the step accepted.
func (s Store) verifyCodes(sec *corev1.Secret, st *state, code1, code2 string, resync bool) (int64, error) {
	now := s.now()
	if st.LockedUntil > now.Unix() {
		return 0, ErrLocked
	}
	seed := sec.Data[seedKey]
	if len(seed) == 0 || !WellFormed(code1) || (code2 != "" && !WellFormed(code2)) {
		return 0, ErrInvalidCode
	}
	cur := StepAt(now) + st.Drift
	var step int64
	var ok bool
	switch {
	case resync:
		base := StepAt(now)
		if step, ok = matchPair(seed, code1, code2, base-resyncWindow, base+resyncWindow, st.LastStep); ok {
			step++
			st.Drift = step - base
		}
	case code2 != "":
		if step, ok = matchPair(seed, code1, code2, cur-enableWindow, cur, st.LastStep); ok {
			step++
		}
	default:
		step, ok = match(seed, code1, cur-window, cur+window, st.LastStep)
	}
	if !ok {
		// A code that is right for a step already used is a replay: refused like any wrong code.
		replay := code2 == "" && !resync
		if replay {
			_, replay = match(seed, code1, cur-window, cur+window, -1<<62)
		}
		st.Failures++
		if st.Failures >= MaxFailures {
			st.Failures, st.LockedUntil = 0, now.Add(Lockout).Unix()
		}
		if replay {
			return 0, ErrReplayed
		}
		return 0, ErrInvalidCode
	}
	st.LastStep, st.Failures, st.LockedUntil = step, 0, 0
	return step, nil
}

// Enable assigns account's unassigned device name to the user userNS/user (UID uid) on two consecutive
// codes from it (EnableMFADevice). ErrNotFound, ErrAssigned when it already is assigned, ErrLimit when the
// user has MaxDevicesPerUser, ErrInvalidCode when the codes do not verify.
func (s Store) Enable(ctx context.Context, account, name, userNS, user, uid, code1, code2 string) error {
	if len(user) > 63 || len(userNS) > 63 {
		return fmt.Errorf("the user name %q is too long to hold an MFA device", user)
	}
	assigned, err := s.ForUser(ctx, account, userNS, user, uid)
	if err != nil {
		return err
	}
	if len(assigned) >= MaxDevicesPerUser {
		return ErrLimit
	}
	return s.update(ctx, account, name, func(sec *corev1.Secret, st *state) (bool, error) {
		// A device assigned to anyone — even a user since deleted — is in use until it is deactivated.
		if deviceOf(sec).Assigned() {
			return false, ErrAssigned
		}
		if _, err := s.verifyCodes(sec, st, code1, code2, false); err != nil {
			return true, err
		}
		st.Drift = 0
		sec.Labels[LabelUser], sec.Labels[LabelUserNamespace] = user, userNS
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		sec.Annotations[AnnUserUID] = uid
		sec.Annotations[AnnEnabled] = s.now().UTC().Format(time.RFC3339)
		return false, nil
	})
}

// Deactivate unassigns account's device name from the user userNS/user (DeactivateMFADevice). The device
// itself remains, unassigned. ErrNotFound when it is not assigned to that user.
func (s Store) Deactivate(ctx context.Context, account, name, userNS, user string) error {
	return s.update(ctx, account, name, func(sec *corev1.Secret, st *state) (bool, error) {
		d := deviceOf(sec)
		if d.User != user || d.UserNamespace != userNS {
			return false, ErrNotFound
		}
		delete(sec.Labels, LabelUser)
		delete(sec.Labels, LabelUserNamespace)
		delete(sec.Annotations, AnnUserUID)
		delete(sec.Annotations, AnnEnabled)
		*st = state{LastStep: st.LastStep}
		return false, nil
	})
}

// Delete removes account's device name (DeleteVirtualMFADevice). ErrAssigned while it is assigned to a
// user (deactivate it first, as on AWS).
func (s Store) Delete(ctx context.Context, account, name string) error {
	sec, err := s.read(ctx, account, name)
	if err != nil {
		return err
	}
	if deviceOf(sec).Assigned() {
		return ErrAssigned
	}
	rv := sec.ResourceVersion
	err = s.CS.CoreV1().Secrets(s.NS).Delete(ctx, sec.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &rv}})
	switch {
	case apierrors.IsNotFound(err):
		return ErrNotFound
	case apierrors.IsConflict(err):
		return ErrAssigned // it changed under us: assigned meanwhile, or try again
	}
	return err
}

// Verify checks one code from account's device name, assigned to the user userNS/user (UID uid): a
// sign-in's second factor, GetSessionToken's or AssumeRole's TokenCode. ErrNotFound when the device is
// not that user's, ErrInvalidCode (ErrReplayed, ErrLocked) when the code is refused.
func (s Store) Verify(ctx context.Context, account, name, userNS, user, uid, code string) error {
	return s.update(ctx, account, name, func(sec *corev1.Secret, st *state) (bool, error) {
		if !deviceOf(sec).AssignedTo(userNS, user, uid) {
			return false, ErrNotFound
		}
		_, err := s.verifyCodes(sec, st, code, "", false)
		return true, err
	})
}

// VerifyAny checks a code against each of the user's devices (the console sign-in, where the user enters
// the code of whichever device it has): nil as soon as one accepts it. A wrong code counts as a failure
// on every device it was tried against.
func (s Store) VerifyAny(ctx context.Context, account, userNS, user, uid, code string) error {
	devices, err := s.ForUser(ctx, account, userNS, user, uid)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return ErrNotFound
	}
	last := error(ErrInvalidCode)
	for _, d := range devices {
		err := s.Verify(ctx, account, d.Name, userNS, user, uid, code)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrInvalidCode) {
			return err
		}
		if !errors.Is(last, ErrLocked) {
			last = err
		}
	}
	return last
}

// Resync resynchronizes account's device name, assigned to userNS/user (UID uid), from two consecutive
// codes it shows now (ResyncMFADevice): it records how far the device's clock is from the server's.
func (s Store) Resync(ctx context.Context, account, name, userNS, user, uid, code1, code2 string) error {
	return s.update(ctx, account, name, func(sec *corev1.Secret, st *state) (bool, error) {
		if !deviceOf(sec).AssignedTo(userNS, user, uid) {
			return false, ErrNotFound
		}
		_, err := s.verifyCodes(sec, st, code1, code2, true)
		return true, err
	})
}

// SetTags replaces account's device name's tags.
func (s Store) SetTags(ctx context.Context, account, name string, tags []Tag) error {
	if len(tags) > MaxTags {
		return ErrLimit
	}
	return s.update(ctx, account, name, func(sec *corev1.Secret, _ *state) (bool, error) {
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		if len(tags) == 0 {
			delete(sec.Annotations, AnnTags)
			return false, nil
		}
		b, _ := json.Marshal(tags)
		sec.Annotations[AnnTags] = string(b)
		return false, nil
	})
}
