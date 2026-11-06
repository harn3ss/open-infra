// Package mfa is IAM's virtual multi-factor authentication: the TOTP devices of AWS's
// CreateVirtualMFADevice / EnableMFADevice, kept so the AWS front door (the IAM door, and STS's
// GetSessionToken and AssumeRole) and the console (sign-in, a user's "Assign MFA device") read and verify
// the same ones.
//
// The codes are RFC 6238 TOTP as AWS virtual MFA devices use them: HMAC-SHA1, 30-second steps, 6 digits.
// A code is accepted one step either side of the server's clock (plus the device's drift, which
// ResyncMFADevice measures); a code is never accepted twice — each device remembers the last step it
// accepted, and a code for that step or an earlier one is refused — and repeated wrong codes lock the
// device for a while (MaxFailures, Lockout).
//
// Seeds: 40 random bytes (AWS's 64-character base32 seed), returned once — the CreateVirtualMFADevice
// answer, as its Base32StringSeed and QRCodePNG — and never again. They are never logged and never part of
// an error. See store.go for where they live and who can read them.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP as AWS virtual MFA uses it is HMAC-SHA1; it is a MAC, not a signature
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	// StepSeconds is the TOTP time step.
	StepSeconds = 30
	// Digits is the code length.
	Digits = 6
	// SeedBytes is the seed length: 40 bytes, a 64-character base32 seed, AWS's size.
	SeedBytes = 40
	// window is how many steps either side of the clock a code may be (one: 30 s of skew each way).
	window = 1
	// enableWindow is how many steps back the first of EnableMFADevice's two codes may be: a user reads one
	// code, waits for the next, and submits both.
	enableWindow = 2
	// resyncWindow is how far (in steps, either way) ResyncMFADevice looks for the device's two codes: ten
	// minutes, for a device whose clock drifted.
	resyncWindow = 20
)

// b32 is the seed's encoding in the otpauth URI and Base32StringSeed: RFC 4648 base32, no padding.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSeed is a fresh random seed.
func NewSeed() ([]byte, error) {
	b := make([]byte, SeedBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Base32 is a seed as the base32 string an authenticator app is given.
func Base32(seed []byte) string { return b32.EncodeToString(seed) }

// StepAt is the TOTP step a moment falls in.
func StepAt(t time.Time) int64 { return t.Unix() / StepSeconds }

// Code is the code for one step (RFC 4226 HOTP over the step counter, dynamic truncation, 6 digits).
func Code(seed []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, seed)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", Digits, bin%1000000)
}

// codeIs compares a submitted code to a step's in constant time.
func codeIs(seed []byte, step int64, code string) bool {
	return subtle.ConstantTimeCompare([]byte(Code(seed, step)), []byte(code)) == 1
}

// WellFormed reports whether a code is six digits (AWS's AuthenticationCode / TokenCode).
func WellFormed(code string) bool {
	if len(code) != Digits {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// match finds the step a code belongs to, among from..to, newer than last; ok=false when none.
func match(seed []byte, code string, from, to, last int64) (int64, bool) {
	found, ok := int64(0), false
	for s := from; s <= to; s++ {
		// Every step in the window is computed, matched or not, so the time taken says nothing about which.
		if s > last && codeIs(seed, s, code) && !ok {
			found, ok = s, true
		}
	}
	return found, ok
}

// matchPair finds the step t of two consecutive codes (code1 at t, code2 at t+1) among from..to, newer
// than last.
func matchPair(seed []byte, code1, code2 string, from, to, last int64) (int64, bool) {
	found, ok := int64(0), false
	for s := from; s <= to; s++ {
		if s > last && codeIs(seed, s, code1) && codeIs(seed, s+1, code2) && !ok {
			found, ok = s, true
		}
	}
	return found, ok
}
