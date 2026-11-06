package mfa

import (
	"net/url"

	"rsc.io/qr"
)

// Issuer is the otpauth issuer an authenticator app shows beside the device.
const Issuer = "open-infra"

// OTPAuthURI is the key URI a virtual MFA device's QR code carries, AWS's form —
// otpauth://totp/<VirtualMFADeviceName>@<AccountName>?secret=<Base32String> — where AccountName is the
// account's alias when it has one, else its id. The issuer names the platform.
func OTPAuthURI(deviceName, accountName string, seed []byte) string {
	q := url.Values{}
	q.Set("secret", Base32(seed))
	q.Set("issuer", Issuer)
	return "otpauth://totp/" + url.PathEscape(deviceName+"@"+accountName) + "?" + q.Encode()
}

// QRCodePNG is a PNG of the QR code that encodes uri (error correction level M, six pixels a module, with
// its quiet zone).
func QRCodePNG(uri string) ([]byte, error) {
	c, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	c.Scale = 6
	return c.PNG(), nil
}
