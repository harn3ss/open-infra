// Package loginprofile is the store for IAM login profiles: a local User's console password, as a bcrypt
// hash, plus the account password policy it must meet.
//
// Where the hashes live: the credential store namespace (the aws-shim's KEYS_NAMESPACE, the same namespace
// as the access keys), never the console namespace. The console namespace also holds root's console-auth
// Secret, and the aws-shim has — and keeps — no Secret access there at all: a login profile written through
// the IAM API never needs it. The console already has Secret access in the credential store namespace (it
// manages access keys there), so it reads a profile from either place: its own legacy iam-pw-<user>
// Secrets, and the store's iam-login-* Secrets.
//
// A profile's Secret is named and labelled for its user (SecretName; LabelProfile, LabelUser,
// LabelUserNamespace). A reader only accepts a Secret whose name and labels name the same user it is
// verifying (ValidFor), so a User whose passwordSecretRef points at someone else's profile signs in as
// no one. Admission (platform/aws-shim/login-profile-guard.yaml) holds the name prefix and the label
// together, so nothing else can pass for a profile.
//
// The Secret keeps the hash and, for the policy's PasswordReusePrevention, the hashes of the passwords it
// replaced; nothing else. When the password was set and whether it must be changed at the next sign-in
// are on the User (AnnCreated, AnnPasswordLastChanged, AnnResetRequired), where GetLoginProfile reads
// them without touching a Secret.
package loginprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// SecretPrefix names every login-profile Secret; admission holds it and LabelProfile together.
	SecretPrefix = "iam-login-"
	// PolicyPrefix names an account's password-policy Secret (one per account).
	PolicyPrefix = "iam-password-policy-"

	LabelProfile       = "openinfra.dev/login-profile"
	LabelPolicy        = "openinfra.dev/password-policy"
	LabelUser          = "openinfra.dev/iam-user"
	LabelUserNamespace = "openinfra.dev/iam-user-namespace"
	LabelAccount       = "openinfra.dev/account-id"

	// HashKey is the data key of the current hash, the same key the console's own Secrets use.
	HashKey = "hash"
	// previousKey holds the replaced hashes, newest first, for PasswordReusePrevention.
	previousKey = "previous"

	// On the User: when its login profile was created, when its password last changed, and whether the
	// password must be changed at the next console sign-in.
	AnnCreated             = "openinfra.dev/login-profile-created"
	AnnPasswordLastChanged = "openinfra.dev/password-last-changed"
	AnnResetRequired       = "openinfra.dev/password-reset-required"

	maxReuse = 24 // AWS's PasswordReusePrevention maximum
)

// SecretName is the login-profile Secret of user (a kind: User in namespace userNS): readable, and unique
// across accounts (two accounts may each have a user of the same name).
func SecretName(userNS, user string) string {
	sum := sha256.Sum256([]byte(userNS + "/" + user))
	short := user
	if len(short) > 30 {
		short = strings.TrimRight(short[:30], "-.")
	}
	return SecretPrefix + short + "-" + hex.EncodeToString(sum[:])[:10]
}

// IsProfileSecret reports whether a Secret's name and labels make it a login profile at all.
func IsProfileSecret(name string, labels map[string]string) bool {
	return strings.HasPrefix(name, SecretPrefix) && labels[LabelProfile] == "true"
}

// ValidFor reports whether a Secret is user's own login profile: the profile name for that user, carrying
// the profile label and naming the same user and namespace. A reader verifies with nothing else.
func ValidFor(sec *corev1.Secret, userNS, user string) bool {
	if sec == nil || sec.Name != SecretName(userNS, user) || !IsProfileSecret(sec.Name, sec.Labels) {
		return false
	}
	return sec.Labels[LabelUser] == user && sec.Labels[LabelUserNamespace] == userNS
}

// ErrNoProfile is a login profile that does not exist (no Secret, or one that is not this user's).
var ErrNoProfile = errors.New("no login profile")

// Store is the credential store namespace's login profiles and password policies.
type Store struct {
	CS kubernetes.Interface
	NS string // the credential store namespace
	// Cost is the bcrypt cost (0 = bcrypt.DefaultCost); tests lower it.
	Cost int
}

func (s Store) cost() int {
	if s.Cost > 0 {
		return s.Cost
	}
	return bcrypt.DefaultCost
}

// Hash returns the bcrypt hash of password at the store's cost.
func (s Store) Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), s.cost())
}

// Exists reports whether user has a login profile in the store.
func (s Store) Exists(ctx context.Context, userNS, user string) (bool, error) {
	sec, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, SecretName(userNS, user), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ValidFor(sec, userNS, user), nil
}

// Write sets user's password (creating the profile Secret, or replacing its hash). keep is the policy's
// PasswordReusePrevention: that many replaced hashes are kept for Reused (0 keeps none). It returns the
// Secret's name.
func (s Store) Write(ctx context.Context, userNS, user, password string, keep int) (string, error) {
	hash, err := s.Hash(password)
	if err != nil {
		return "", err
	}
	name := SecretName(userNS, user)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.NS, Labels: map[string]string{
			"app.kubernetes.io/managed-by": "open-infra-iam",
			LabelProfile:                   "true",
			LabelUser:                      user,
			LabelUserNamespace:             userNS,
		}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{HashKey: hash},
	}
	_, err = s.CS.CoreV1().Secrets(s.NS).Create(ctx, sec, metav1.CreateOptions{})
	if err == nil {
		return name, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return "", err
	}
	cur, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if !ValidFor(cur, userNS, user) {
		// A Secret of that name that is not this user's profile is never overwritten.
		return "", fmt.Errorf("secret %s/%s is not %s's login profile", s.NS, name, user)
	}
	prev := previousHashes(cur)
	if old := cur.Data[HashKey]; len(old) > 0 && keep > 0 {
		prev = append([]string{string(old)}, prev...)
	}
	if keep > maxReuse {
		keep = maxReuse
	}
	if len(prev) > keep {
		prev = prev[:keep]
	}
	if cur.Data == nil {
		cur.Data = map[string][]byte{}
	}
	cur.Data[HashKey] = hash
	if len(prev) > 0 {
		b, _ := json.Marshal(prev)
		cur.Data[previousKey] = b
	} else {
		delete(cur.Data, previousKey)
	}
	if _, err := s.CS.CoreV1().Secrets(s.NS).Update(ctx, cur, metav1.UpdateOptions{}); err != nil {
		return "", err
	}
	return name, nil
}

func previousHashes(sec *corev1.Secret) []string {
	var prev []string
	if b := sec.Data[previousKey]; len(b) > 0 {
		_ = json.Unmarshal(b, &prev)
	}
	return prev
}

// Verify reports whether password is user's current password. The hash is read for this call only.
func (s Store) Verify(ctx context.Context, userNS, user, password string) (bool, error) {
	sec, err := s.read(ctx, userNS, user)
	if err != nil {
		return false, err
	}
	return bcrypt.CompareHashAndPassword(sec.Data[HashKey], []byte(password)) == nil, nil
}

// Reused reports whether password is the current one or one of the last n it replaced (the policy's
// PasswordReusePrevention; n = 0 checks nothing).
func (s Store) Reused(ctx context.Context, userNS, user, password string, n int) (bool, error) {
	if n <= 0 {
		return false, nil
	}
	sec, err := s.read(ctx, userNS, user)
	if errors.Is(err, ErrNoProfile) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	hashes := append([]string{string(sec.Data[HashKey])}, previousHashes(sec)...)
	if len(hashes) > n {
		hashes = hashes[:n]
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// CurrentHash returns user's current hash (the console's sign-in reads it this way).
func (s Store) CurrentHash(ctx context.Context, userNS, user string) (string, error) {
	sec, err := s.read(ctx, userNS, user)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(sec.Data[HashKey])), nil
}

func (s Store) read(ctx context.Context, userNS, user string) (*corev1.Secret, error) {
	sec, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, SecretName(userNS, user), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	if !ValidFor(sec, userNS, user) || len(sec.Data[HashKey]) == 0 {
		return nil, ErrNoProfile
	}
	return sec, nil
}

// Delete removes user's login profile Secret (absent is not an error). Only the user's own profile is
// deleted.
func (s Store) Delete(ctx context.Context, userNS, user string) error {
	name := SecretName(userNS, user)
	sec, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ValidFor(sec, userNS, user) {
		return fmt.Errorf("secret %s/%s is not %s's login profile", s.NS, name, user)
	}
	err = s.CS.CoreV1().Secrets(s.NS).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// --- the account password policy ---

// Policy is an account's password policy (AWS's PasswordPolicy).
type Policy struct {
	MinimumPasswordLength      int  `json:"minimumPasswordLength"`
	RequireSymbols             bool `json:"requireSymbols"`
	RequireNumbers             bool `json:"requireNumbers"`
	RequireUppercaseCharacters bool `json:"requireUppercaseCharacters"`
	RequireLowercaseCharacters bool `json:"requireLowercaseCharacters"`
	AllowUsersToChangePassword bool `json:"allowUsersToChangePassword"`
	MaxPasswordAge             int  `json:"maxPasswordAge,omitempty"` // days; 0 = passwords never expire
	PasswordReusePrevention    int  `json:"passwordReusePrevention,omitempty"`
	HardExpiry                 bool `json:"hardExpiry,omitempty"`
}

// ExpirePasswords is AWS's derived field: passwords expire when MaxPasswordAge is set.
func (p Policy) ExpirePasswords() bool { return p.MaxPasswordAge > 0 }

// symbols are the non-alphanumeric characters AWS's password policy counts as symbols.
const symbols = "!@#$%^&*()_+-=[]{}|'"

// ViolationError is a password a policy refuses (IAM's PasswordPolicyViolation).
type ViolationError struct{ Msg string }

func (e *ViolationError) Error() string { return e.Msg }

// Check refuses a password the custom policy does not allow, in IAM's words.
func (p Policy) Check(password string) error {
	min := p.MinimumPasswordLength
	if min < 6 {
		min = 6
	}
	var why []string
	if len(password) < min {
		why = append(why, "Password should have at least "+strconv.Itoa(min)+" characters")
	}
	up, low, num, sym := classes(password)
	if p.RequireUppercaseCharacters && !up {
		why = append(why, "Password should have at least one uppercase letter")
	}
	if p.RequireLowercaseCharacters && !low {
		why = append(why, "Password should have at least one lowercase letter")
	}
	if p.RequireNumbers && !num {
		why = append(why, "Password should have at least one number")
	}
	if p.RequireSymbols && !sym {
		why = append(why, "Password should have at least one symbol")
	}
	if len(why) > 0 {
		return &ViolationError{Msg: strings.Join(why, "; ")}
	}
	return nil
}

// CheckDefault refuses a password AWS's default policy (no custom policy set) does not allow: at least
// 8 characters, at least three of uppercase, lowercase, numbers and symbols, and not the account's name
// (its alias or id) or email.
func CheckDefault(password string, accountNames ...string) error {
	if len(password) < 8 {
		return &ViolationError{Msg: "Password should have at least 8 characters"}
	}
	up, low, num, sym := classes(password)
	n := 0
	for _, b := range []bool{up, low, num, sym} {
		if b {
			n++
		}
	}
	if n < 3 {
		return &ViolationError{Msg: "Password should have at least three of the following: uppercase letters, lowercase letters, numbers, and symbols"}
	}
	for _, a := range accountNames {
		if a != "" && strings.EqualFold(password, a) {
			return &ViolationError{Msg: "Password should not be the account name or email address"}
		}
	}
	return nil
}

func classes(s string) (up, low, num, sym bool) {
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			low = true
		case unicode.IsDigit(r):
			num = true
		case strings.ContainsRune(symbols, r):
			sym = true
		}
	}
	return
}

// Validate refuses a policy outside IAM's ranges (UpdateAccountPasswordPolicy's ValidationError).
func (p Policy) Validate() error {
	if p.MinimumPasswordLength != 0 && (p.MinimumPasswordLength < 6 || p.MinimumPasswordLength > 128) {
		return errors.New("MinimumPasswordLength must be between 6 and 128")
	}
	if p.MaxPasswordAge != 0 && (p.MaxPasswordAge < 1 || p.MaxPasswordAge > 1095) {
		return errors.New("MaxPasswordAge must be between 1 and 1095")
	}
	if p.PasswordReusePrevention != 0 && (p.PasswordReusePrevention < 1 || p.PasswordReusePrevention > maxReuse) {
		return errors.New("PasswordReusePrevention must be between 1 and 24")
	}
	return nil
}

// PolicySecretName is account's password-policy Secret.
func PolicySecretName(account string) string { return PolicyPrefix + account }

// GetPolicy reads account's custom password policy; found=false when none is set (AWS's default applies).
func (s Store) GetPolicy(ctx context.Context, account string) (Policy, bool, error) {
	sec, err := s.CS.CoreV1().Secrets(s.NS).Get(ctx, PolicySecretName(account), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	if sec.Labels[LabelPolicy] != "true" || sec.Labels[LabelAccount] != account {
		return Policy{}, false, nil
	}
	var p Policy
	if err := json.Unmarshal(sec.Data["policy.json"], &p); err != nil {
		return Policy{}, false, fmt.Errorf("account %s's password policy is unreadable: %w", account, err)
	}
	return p, true, nil
}

// PutPolicy sets account's custom password policy.
func (s Store) PutPolicy(ctx context.Context, account string, p Policy) error {
	if p.MinimumPasswordLength == 0 {
		p.MinimumPasswordLength = 6 // IAM's default for an unset MinimumPasswordLength
	}
	b, _ := json.Marshal(p)
	name := PolicySecretName(account)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.NS, Labels: map[string]string{
			"app.kubernetes.io/managed-by": "open-infra-iam", LabelPolicy: "true", LabelAccount: account,
		}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"policy.json": b},
	}
	_, err := s.CS.CoreV1().Secrets(s.NS).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		cur, gerr := s.CS.CoreV1().Secrets(s.NS).Get(ctx, name, metav1.GetOptions{})
		if gerr != nil {
			return gerr
		}
		if cur.Labels[LabelPolicy] != "true" || cur.Labels[LabelAccount] != account {
			return fmt.Errorf("secret %s/%s is not account %s's password policy", s.NS, name, account)
		}
		cur.Data = sec.Data
		_, err = s.CS.CoreV1().Secrets(s.NS).Update(ctx, cur, metav1.UpdateOptions{})
	}
	return err
}

// DeletePolicy removes account's custom password policy; found=false when there was none.
func (s Store) DeletePolicy(ctx context.Context, account string) (bool, error) {
	if _, found, err := s.GetPolicy(ctx, account); err != nil || !found {
		return false, err
	}
	err := s.CS.CoreV1().Secrets(s.NS).Delete(ctx, PolicySecretName(account), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// CheckFor refuses a password for account: its custom policy when set, else AWS's default policy.
func (s Store) CheckFor(ctx context.Context, account, password string, accountNames ...string) (Policy, bool, error) {
	p, custom, err := s.GetPolicy(ctx, account)
	if err != nil {
		return p, false, err
	}
	if custom {
		return p, true, p.Check(password)
	}
	return p, false, CheckDefault(password, append(accountNames, account)...)
}

// Expired reports whether a password last changed at changed has passed the policy's MaxPasswordAge.
func (p Policy) Expired(changed, now time.Time) bool {
	if p.MaxPasswordAge <= 0 || changed.IsZero() {
		return false
	}
	return now.Sub(changed) > time.Duration(p.MaxPasswordAge)*24*time.Hour
}
