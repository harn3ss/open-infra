// IAM virtual MFA devices through the IAM front door: CreateVirtualMFADevice, EnableMFADevice,
// DeactivateMFADevice, DeleteVirtualMFADevice, ResyncMFADevice, ListMFADevices, ListVirtualMFADevices and
// TagMFADevice / UntagMFADevice / ListMFADeviceTags — TOTP devices, managed as AWS manages them.
//
// Where they live (internal/mfa): one Secret per device in the credential store namespace (the keys
// namespace, beside the access keys and login profiles), named for its account and name, so a device name
// is unique within an account and each account's devices are its own. The seed is returned once, in
// CreateVirtualMFADevice's answer (Base32StringSeed and the QRCodePNG of the otpauth URI), and never again:
// not by a list, not in an error, not in a log line. Admission (platform/aws-shim/mfa-device-guard.yaml)
// holds the device Secrets' name prefix and label together.
//
// A device's serial number is its ARN, arn:aws:iam::<account>:mfa<path><name>. The management account's
// devices are kept under iam.ManagementAccount whatever account id the install presents, so the console
// (which signs a user in with them) and this door find the same ones; the serial shows the presented id.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// isMFAOp reports the operations this file serves.
func isMFAOp(op string) bool {
	switch op {
	case "CreateVirtualMFADevice", "DeleteVirtualMFADevice", "EnableMFADevice", "DeactivateMFADevice",
		"ResyncMFADevice", "ListMFADevices", "ListVirtualMFADevices",
		"TagMFADevice", "UntagMFADevice", "ListMFADeviceTags":
		return true
	}
	return false
}

// mfaResourceOp reports the MFA operations AWS authorizes on the device's ARN (the mfa resource type);
// the others are authorized on the user (EnableMFADevice, DeactivateMFADevice, ResyncMFADevice,
// ListMFADevices) or on no resource (ListVirtualMFADevices).
func mfaResourceOp(op string) bool {
	switch op {
	case "CreateVirtualMFADevice", "DeleteVirtualMFADevice", "TagMFADevice", "UntagMFADevice", "ListMFADeviceTags":
		return true
	}
	return false
}

func (h *iamHandler) mfaStore() mfa.Store {
	ns := ""
	if h.keys != nil {
		ns = h.keys.Namespace()
	}
	return mfa.Store{CS: h.cs, NS: ns}
}

// mfaAccount is the store account of an IAM scope: the management account's devices are kept under
// iam.ManagementAccount (the console's name for it), a member account's under its id.
func (h *iamHandler) mfaAccount(sc iamScope) string {
	if sc.ns == h.usersNS {
		return iam.ManagementAccount
	}
	return sc.account
}

// mfaARN is the resource an mfa-resource operation is authorized on: the device the request names (its
// SerialNumber, or for CreateVirtualMFADevice the Path and VirtualMFADeviceName it will have).
func (h *iamHandler) mfaARN(ctx context.Context, op string, r *http.Request) string {
	sc := h.scope(ctx)
	if op == "CreateVirtualMFADevice" {
		path := r.PostFormValue("Path")
		if path == "" {
			path = "/"
		}
		return mfa.SerialNumber(sc.account, path, orStar(r.PostFormValue("VirtualMFADeviceName")))
	}
	if _, path, name, ok := mfa.ParseSerial(r.PostFormValue("SerialNumber")); ok {
		return mfa.SerialNumber(sc.account, path, name)
	}
	return sc.arn("mfa/*")
}

// serveMFA serves an authorized MFA operation.
func (h *iamHandler) serveMFA(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string, claims iam.Claims) {
	switch op {
	case "CreateVirtualMFADevice":
		h.createVirtualMFADevice(ctx, w, r, requestID)
	case "DeleteVirtualMFADevice":
		h.deleteVirtualMFADevice(ctx, w, r, requestID)
	case "EnableMFADevice":
		h.enableMFADevice(ctx, w, r, requestID)
	case "DeactivateMFADevice":
		h.deactivateMFADevice(ctx, w, r, requestID, claims)
	case "ResyncMFADevice":
		h.resyncMFADevice(ctx, w, r, requestID)
	case "ListMFADevices":
		h.listMFADevices(ctx, w, r, requestID, claims)
	case "ListVirtualMFADevices":
		h.listVirtualMFADevices(ctx, w, r, requestID)
	case "TagMFADevice", "UntagMFADevice", "ListMFADeviceTags":
		h.mfaTags(ctx, w, r, op, requestID)
	}
}

func (h *iamHandler) validation(w http.ResponseWriter, requestID, msg string) {
	writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, msg, iamXMLNamespace)
}

// mfaUser is the IAM user an MFA operation names in the caller's account: UserName, or — where AWS
// defaults it — the calling user. ok=false when there is none (the answer is written).
func (h *iamHandler) mfaUser(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, defaultToCaller bool) (*unstructured.Unstructured, string, bool) {
	name := r.PostFormValue("UserName")
	if name == "" && defaultToCaller {
		if claims.AssumedRole != "" || claims.PrincipalID() == "" {
			h.validation(w, requestID, "Must specify userName when calling with non-User credentials")
			return nil, "", false
		}
		name = claims.PrincipalID()
	}
	if name == "" {
		h.validation(w, requestID, "1 validation error detected: Value null at 'userName' failed to satisfy constraint: Member must not be null")
		return nil, "", false
	}
	if reservedUserName(name) {
		h.noSuchEntity(w, requestID, "The user with name "+name+" cannot be found.")
		return nil, "", false
	}
	sc := h.scope(ctx)
	u, err := h.dyn.Resource(gvrUsers).Namespace(sc.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "The user with name "+name+" cannot be found.")
		return nil, "", false
	}
	return u, name, true
}

// mfaSerial is the device a request's SerialNumber names in the caller's account (its store name), or a
// NoSuchEntity answer: a serial that is not a virtual MFA device's ARN, or names another account's.
func (h *iamHandler) mfaSerial(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) (mfa.Device, string, bool) {
	serial := r.PostFormValue("SerialNumber")
	if serial == "" {
		h.validation(w, requestID, "1 validation error detected: Value null at 'serialNumber' failed to satisfy constraint: Member must not be null")
		return mfa.Device{}, "", false
	}
	if len(serial) < 9 || len(serial) > 256 {
		h.validation(w, requestID, "1 validation error detected: Value at 'serialNumber' failed to satisfy constraint: Member must have length between 9 and 256")
		return mfa.Device{}, "", false
	}
	sc := h.scope(ctx)
	notFound := func() (mfa.Device, string, bool) {
		h.noSuchEntity(w, requestID, "VirtualMFADevice with serial "+serial+" not found.")
		return mfa.Device{}, "", false
	}
	acct, path, name, ok := mfa.ParseSerial(serial)
	if !ok || acct != sc.account {
		return notFound()
	}
	d, err := h.mfaStore().Get(ctx, h.mfaAccount(sc), name)
	if errors.Is(err, mfa.ErrNotFound) || (err == nil && d.Path != path) {
		return notFound()
	}
	if err != nil {
		h.internal(w, requestID, err)
		return mfa.Device{}, "", false
	}
	return d, serial, true
}

// authCodes reads AuthenticationCode1 and AuthenticationCode2 (six digits each).
func (h *iamHandler) authCodes(w http.ResponseWriter, r *http.Request, requestID string) (string, string, bool) {
	c1, c2 := r.PostFormValue("AuthenticationCode1"), r.PostFormValue("AuthenticationCode2")
	for _, c := range []struct{ name, v string }{{"authenticationCode1", c1}, {"authenticationCode2", c2}} {
		if c.v == "" {
			h.validation(w, requestID, "1 validation error detected: Value null at '"+c.name+"' failed to satisfy constraint: Member must not be null")
			return "", "", false
		}
		if !mfa.WellFormed(c.v) {
			h.validation(w, requestID, "1 validation error detected: Value at '"+c.name+"' failed to satisfy constraint: Member must have length 6 and satisfy regular expression pattern: [\\d]+")
			return "", "", false
		}
	}
	return c1, c2, true
}

// mfaFail writes a store error as IAM's.
func (h *iamHandler) mfaFail(w http.ResponseWriter, requestID, serial string, err error) {
	switch {
	case errors.Is(err, mfa.ErrInvalidCode):
		writeQueryError(w, http.StatusForbidden, "InvalidAuthenticationCode", requestID, "Authentication code for device is not valid.", iamXMLNamespace)
	case errors.Is(err, mfa.ErrAssigned):
		h.conflict(w, requestID, "EntityAlreadyExists", "MFA Device is already in use.")
	case errors.Is(err, mfa.ErrLimit):
		h.conflict(w, requestID, "LimitExceeded", "Cannot exceed quota for MFADevicesPerUser: "+strconv.Itoa(mfa.MaxDevicesPerUser))
	case errors.Is(err, mfa.ErrNotFound):
		h.noSuchEntity(w, requestID, "MFA Device with serial number "+serial+" does not exist.")
	default:
		h.internal(w, requestID, err)
	}
}

// mfaTagsFromForm reads Tags.member.N.Key / .Value, in order.
func mfaTagsFromForm(r *http.Request) ([]mfa.Tag, string) {
	var out []mfa.Tag
	for i := 1; i <= mfa.MaxTags+1; i++ {
		k := r.PostFormValue("Tags.member." + strconv.Itoa(i) + ".Key")
		if k == "" {
			break
		}
		if len(k) > 128 {
			return nil, "a tag key is at most 128 characters"
		}
		v := r.PostFormValue("Tags.member." + strconv.Itoa(i) + ".Value")
		if len(v) > 256 {
			return nil, "a tag value is at most 256 characters"
		}
		out = append(out, mfa.Tag{Key: k, Value: v})
	}
	if len(out) > mfa.MaxTags {
		return nil, "a resource has at most 50 tags"
	}
	return out, ""
}

func tagsXML(tags []mfa.Tag) string {
	var b strings.Builder
	b.WriteString("<Tags>")
	for _, t := range tags {
		b.WriteString("<member><Key>" + xmlEscape(t.Key) + "</Key><Value>" + xmlEscape(t.Value) + "</Value></member>")
	}
	b.WriteString("</Tags>")
	return b.String()
}

func (h *iamHandler) createVirtualMFADevice(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	sc := h.scope(ctx)
	name, path := r.PostFormValue("VirtualMFADeviceName"), r.PostFormValue("Path")
	if path == "" {
		path = "/"
	}
	switch {
	case name == "":
		h.validation(w, requestID, "1 validation error detected: Value null at 'virtualMFADeviceName' failed to satisfy constraint: Member must not be null")
		return
	case !mfa.ValidName(name):
		h.validation(w, requestID, "1 validation error detected: Value at 'virtualMFADeviceName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]+")
		return
	case !mfa.ValidPath(path):
		h.validation(w, requestID, "1 validation error detected: Value at 'path' failed to satisfy constraint: Member must satisfy regular expression pattern: (\\u002F)|(\\u002F[\\u0021-\\u007F]+\\u002F)")
		return
	}
	serial := mfa.SerialNumber(sc.account, path, name)
	if len(serial) > 256 {
		h.fail(w, requestID, invalidInputErr("The serial number "+serial+" would be longer than 256 characters."))
		return
	}
	tags, why := mfaTagsFromForm(r)
	if why != "" {
		h.fail(w, requestID, invalidInputErr(why))
		return
	}
	d, seed, err := h.mfaStore().Create(ctx, h.mfaAccount(sc), name, path, tags)
	switch {
	case errors.Is(err, mfa.ErrExists):
		h.conflict(w, requestID, "EntityAlreadyExists", "MFADevice entity at the same path and name already exists.")
		return
	case errors.Is(err, mfa.ErrLimit):
		h.conflict(w, requestID, "LimitExceeded", "Cannot exceed quota for VirtualMFADevicesPerAccount: "+strconv.Itoa(mfa.MaxDevicesPerAccount))
		return
	case err != nil:
		h.internal(w, requestID, err)
		return
	}
	png, err := mfa.QRCodePNG(mfa.OTPAuthURI(name, sc.account, seed))
	if err != nil {
		// The device exists but its QR code cannot be drawn: remove it rather than leave a seed no one has.
		_ = h.mfaStore().Delete(context.Background(), h.mfaAccount(sc), name)
		h.internal(w, requestID, errors.New("could not render the device's QR code"))
		return
	}
	h.audit(ctx, "CreateVirtualMFADevice", serial, "allow", "")
	body := "<VirtualMFADevice><SerialNumber>" + xmlEscape(serial) + "</SerialNumber>" +
		// Blob members are base64 on the wire: the SDK hands back the base32 seed and the PNG's bytes.
		"<Base32StringSeed>" + base64.StdEncoding.EncodeToString([]byte(mfa.Base32(seed))) + "</Base32StringSeed>" +
		"<QRCodePNG>" + base64.StdEncoding.EncodeToString(png) + "</QRCodePNG>"
	if len(d.Tags) > 0 {
		body += tagsXML(d.Tags)
	}
	h.writeResult(w, requestID, "CreateVirtualMFADevice", body+"</VirtualMFADevice>")
}

func (h *iamHandler) enableMFADevice(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	u, user, ok := h.mfaUser(ctx, w, r, requestID, iam.Claims{}, false)
	if !ok {
		return
	}
	d, serial, ok := h.mfaSerial(ctx, w, r, requestID)
	if !ok {
		return
	}
	c1, c2, ok := h.authCodes(w, r, requestID)
	if !ok {
		return
	}
	sc := h.scope(ctx)
	if err := h.mfaStore().Enable(ctx, h.mfaAccount(sc), d.Name, sc.ns, user, string(u.GetUID()), c1, c2); err != nil {
		h.audit(ctx, "EnableMFADevice", user, "deny", mfaRefusal(err))
		h.mfaFail(w, requestID, serial, err)
		return
	}
	h.audit(ctx, "EnableMFADevice", user, "allow", "serialNumber="+serial)
	h.writeResult(w, requestID, "EnableMFADevice", "")
}

// mfaRefusal is why a code was refused, for the audit line (never the code, never the seed).
func mfaRefusal(err error) string {
	switch {
	case errors.Is(err, mfa.ErrLocked):
		return "device locked after repeated wrong codes"
	case errors.Is(err, mfa.ErrReplayed):
		return "a code already used"
	case errors.Is(err, mfa.ErrInvalidCode):
		return "wrong code"
	}
	return err.Error()
}

func (h *iamHandler) resyncMFADevice(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	u, user, ok := h.mfaUser(ctx, w, r, requestID, iam.Claims{}, false)
	if !ok {
		return
	}
	d, serial, ok := h.mfaSerial(ctx, w, r, requestID)
	if !ok {
		return
	}
	c1, c2, ok := h.authCodes(w, r, requestID)
	if !ok {
		return
	}
	sc := h.scope(ctx)
	if err := h.mfaStore().Resync(ctx, h.mfaAccount(sc), d.Name, sc.ns, user, string(u.GetUID()), c1, c2); err != nil {
		h.audit(ctx, "ResyncMFADevice", user, "deny", mfaRefusal(err))
		h.mfaFail(w, requestID, serial, err)
		return
	}
	h.audit(ctx, "ResyncMFADevice", user, "allow", "serialNumber="+serial)
	h.writeResult(w, requestID, "ResyncMFADevice", "")
}

func (h *iamHandler) deactivateMFADevice(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	user := r.PostFormValue("UserName")
	if user == "" {
		if claims.AssumedRole != "" || claims.PrincipalID() == "" {
			h.validation(w, requestID, "Must specify userName when calling with non-User credentials")
			return
		}
		user = claims.PrincipalID()
	}
	d, serial, ok := h.mfaSerial(ctx, w, r, requestID)
	if !ok {
		return
	}
	sc := h.scope(ctx)
	// The device's user need not exist any more: a device left assigned to a deleted user is deactivated
	// by naming that user.
	if err := h.mfaStore().Deactivate(ctx, h.mfaAccount(sc), d.Name, sc.ns, user); err != nil {
		if errors.Is(err, mfa.ErrNotFound) {
			h.noSuchEntity(w, requestID, "MFA Device with serial number "+serial+" is not assigned to user "+user+".")
			return
		}
		h.mfaFail(w, requestID, serial, err)
		return
	}
	h.audit(ctx, "DeactivateMFADevice", user, "allow", "serialNumber="+serial)
	h.writeResult(w, requestID, "DeactivateMFADevice", "")
}

func (h *iamHandler) deleteVirtualMFADevice(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	d, serial, ok := h.mfaSerial(ctx, w, r, requestID)
	if !ok {
		return
	}
	if err := h.mfaStore().Delete(ctx, h.mfaAccount(h.scope(ctx)), d.Name); err != nil {
		if errors.Is(err, mfa.ErrAssigned) {
			h.conflict(w, requestID, "DeleteConflict", "MFA VirtualDevice in use. Must deactivate first.")
			return
		}
		h.mfaFail(w, requestID, serial, err)
		return
	}
	h.audit(ctx, "DeleteVirtualMFADevice", serial, "allow", "")
	h.writeResult(w, requestID, "DeleteVirtualMFADevice", "")
}

// page applies MaxItems / Marker (an offset this door hands out) to a listing of n items: the range to
// answer and the Marker for the rest ("" when none). ok=false when either is malformed.
func page(r *http.Request, n int) (from, to int, next string, ok bool) {
	max := 100
	if v := r.PostFormValue("MaxItems"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 1 || m > 1000 {
			return 0, 0, "", false
		}
		max = m
	}
	if v := r.PostFormValue("Marker"); v != "" {
		f, err := strconv.Atoi(v)
		if err != nil || f < 0 {
			return 0, 0, "", false
		}
		from = f
	}
	if from > n {
		from = n
	}
	to = from + max
	if to >= n {
		return from, n, "", true
	}
	return from, to, strconv.Itoa(to), true
}

func truncated(next string) string {
	if next == "" {
		return "<IsTruncated>false</IsTruncated>"
	}
	return "<IsTruncated>true</IsTruncated><Marker>" + next + "</Marker>"
}

func (h *iamHandler) listMFADevices(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	u, user, ok := h.mfaUser(ctx, w, r, requestID, claims, true)
	if !ok {
		return
	}
	sc := h.scope(ctx)
	devices, err := h.mfaStore().ForUser(ctx, h.mfaAccount(sc), sc.ns, user, string(u.GetUID()))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	from, to, next, ok := page(r, len(devices))
	if !ok {
		h.validation(w, requestID, "MaxItems must be 1 to 1000, and Marker one this API returned.")
		return
	}
	var b strings.Builder
	b.WriteString("<MFADevices>")
	for _, d := range devices[from:to] {
		b.WriteString("<member><UserName>" + xmlEscape(user) + "</UserName><SerialNumber>" + xmlEscape(d.SerialNumber(sc.account)) +
			"</SerialNumber><EnableDate>" + d.EnableDate.UTC().Format(time.RFC3339) + "</EnableDate></member>")
	}
	b.WriteString("</MFADevices>" + truncated(next))
	h.writeResult(w, requestID, "ListMFADevices", b.String())
}

func (h *iamHandler) listVirtualMFADevices(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string) {
	status := r.PostFormValue("AssignmentStatus")
	switch status {
	case "", "Any", "Assigned", "Unassigned":
	default:
		h.validation(w, requestID, "1 validation error detected: Value '"+status+"' at 'assignmentStatus' failed to satisfy constraint: Member must satisfy enum value set: [Any, Assigned, Unassigned]")
		return
	}
	sc := h.scope(ctx)
	all, err := h.mfaStore().List(ctx, h.mfaAccount(sc))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	var devices []mfa.Device
	for _, d := range all {
		if (status == "Assigned" && !d.Assigned()) || (status == "Unassigned" && d.Assigned()) {
			continue
		}
		devices = append(devices, d)
	}
	from, to, next, ok := page(r, len(devices))
	if !ok {
		h.validation(w, requestID, "MaxItems must be 1 to 1000, and Marker one this API returned.")
		return
	}
	var b strings.Builder
	b.WriteString("<VirtualMFADevices>")
	for _, d := range devices[from:to] {
		b.WriteString("<member><SerialNumber>" + xmlEscape(d.SerialNumber(sc.account)) + "</SerialNumber>")
		if d.Assigned() {
			b.WriteString("<User>" + h.userXML(ctx, d.User) + "</User><EnableDate>" + d.EnableDate.UTC().Format(time.RFC3339) + "</EnableDate>")
		}
		b.WriteString("</member>")
	}
	b.WriteString("</VirtualMFADevices>" + truncated(next))
	h.writeResult(w, requestID, "ListVirtualMFADevices", b.String())
}

func (h *iamHandler) mfaTags(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string) {
	d, serial, ok := h.mfaSerial(ctx, w, r, requestID)
	if !ok {
		return
	}
	account := h.mfaAccount(h.scope(ctx))
	switch op {
	case "ListMFADeviceTags":
		h.writeResult(w, requestID, op, tagsXML(d.Tags)+"<IsTruncated>false</IsTruncated>")
		return
	case "TagMFADevice":
		add, why := mfaTagsFromForm(r)
		if why != "" || len(add) == 0 {
			if why == "" {
				why = "Tags is required."
			}
			h.fail(w, requestID, invalidInputErr(why))
			return
		}
		tags := d.Tags
		for _, t := range add {
			replaced := false
			for i := range tags {
				if tags[i].Key == t.Key {
					tags[i].Value, replaced = t.Value, true
				}
			}
			if !replaced {
				tags = append(tags, t)
			}
		}
		if len(tags) > mfa.MaxTags {
			h.conflict(w, requestID, "LimitExceeded", "The number of tags has reached the maximum limit.")
			return
		}
		d.Tags = tags
	case "UntagMFADevice":
		keys := queryList(r, "TagKeys")
		if len(keys) == 0 {
			h.validation(w, requestID, "1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null")
			return
		}
		var kept []mfa.Tag
		for _, t := range d.Tags {
			drop := false
			for _, k := range keys {
				drop = drop || k == t.Key
			}
			if !drop {
				kept = append(kept, t)
			}
		}
		d.Tags = kept
	}
	if err := h.mfaStore().SetTags(ctx, account, d.Name, d.Tags); err != nil {
		h.mfaFail(w, requestID, serial, err)
		return
	}
	h.audit(ctx, op, serial, "allow", "")
	h.writeResult(w, requestID, op, "")
}

// mfaDevicesOf is the MFA devices assigned to user u (DeleteUser's conflict check).
func (h *iamHandler) mfaDevicesOf(ctx context.Context, sc iamScope, u *unstructured.Unstructured) ([]mfa.Device, error) {
	if h.keys == nil {
		return nil, nil
	}
	return h.mfaStore().ForUser(ctx, h.mfaAccount(sc), sc.ns, u.GetName(), string(u.GetUID()))
}
