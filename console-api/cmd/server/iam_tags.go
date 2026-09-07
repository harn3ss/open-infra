package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Free-form key/value tags on an IAM identity — the AWS "Tags" tab (User / Role / Policy).
//
// AWS tags are arbitrary key/value pairs. We back them with ANNOTATIONS on the CR, not a new
// spec field: annotations take an arbitrary value (a k8s LABEL value can't — it's the same
// [A-Za-z0-9._-]{0,63} charset a tag value routinely breaks), and adding one needs no XRD /
// OpenAPI / CRD change. Each tag is one annotation, "openinfra.dev/tag-<key>: <value>". The
// prefix is an implementation detail: the views hand the SPA clean keys, and the update endpoint
// re-adds the prefix.
//
// Every write is gated by the SAME SubjectAccessReview that gates every other write to the
// resource (update on iam.openinfra.dev/users|roles|policies — admins only). The console's
// ServiceAccount does the patch; the human's own RBAC decides whether it happens.
//
// Groups deliberately have NO tags tab — AWS IAM groups don't carry tags, so there is no
// /iam/groups/{name}/tags route.

const (
	// tagAnnotationPrefix namespaces a tag annotation. The clean key "team" is stored as
	// "openinfra.dev/tag-team". The domain half ("openinfra.dev/") is a fixed annotation prefix;
	// "tag-<key>" is the annotation name segment, which the apiserver caps at 63 chars.
	tagAnnotationPrefix = "openinfra.dev/tag-"

	// maxTagKeyLen bounds a tag key. "tag-" (4) + key must be a ≤63-char annotation name segment,
	// so the key itself is ≤59. This is tighter than AWS's 128-char key because the key becomes
	// part of an annotation NAME (which AWS tags never do); the constraint is stated to the user.
	maxTagKeyLen = 59

	// maxTagValueLen matches AWS's 256-char tag-value bound. Annotation values are otherwise
	// unbounded (up to the 256KB metadata budget), so this is a product bound, not a k8s one.
	maxTagValueLen = 256

	// maxTagsPerResource matches AWS's 50-tags-per-resource limit.
	maxTagsPerResource = 50
)

// tagKeyRe constrains a tag key to a valid annotation name segment once "tag-" is prepended:
// alphanumeric ends, with '.', '_' or '-' allowed inside. A single alphanumeric char is valid.
var tagKeyRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// reservedTagPrefixes are refused as tag keys (case-insensitive) so a tag can't shadow a system
// annotation namespace or AWS's reserved "aws:" prefix. Matches AWS's reserved-prefix behaviour.
var reservedTagPrefixes = []string{"aws:", "openinfra.dev", "kubernetes.io", "k8s.io"}

// tagsFromAnnotations projects a CR's annotations onto the clean tag map the SPA sees — only the
// openinfra.dev/tag-* annotations, with the prefix stripped. Always returns a non-nil map so it
// serialises as {} not null (the SPA iterates it).
func tagsFromAnnotations(ann map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range ann {
		if strings.HasPrefix(k, tagAnnotationPrefix) {
			out[strings.TrimPrefix(k, tagAnnotationPrefix)] = v
		}
	}
	return out
}

// cleanTags trims keys and drops blank-keyed entries, so a stray empty row from the editor is
// ignored rather than rejected. Values are preserved verbatim (AWS keeps tag values as typed).
func cleanTags(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = v
		}
	}
	return out
}

// validateTags bounds a tag set the way AWS bounds tags: count, key length + charset, value
// length + charset, and reserved-prefix keys. Returns "" when valid, else a user-facing message.
func validateTags(tags map[string]string) string {
	if len(tags) > maxTagsPerResource {
		return fmt.Sprintf("too many tags — the maximum is %d per resource", maxTagsPerResource)
	}
	for k, v := range tags {
		if k == "" {
			return "a tag key cannot be empty"
		}
		if len(k) > maxTagKeyLen {
			return fmt.Sprintf("tag key %q is too long — a key is at most %d characters", k, maxTagKeyLen)
		}
		// Reserved-prefix check first: a reserved key (e.g. "aws:foo", "kubernetes.io/x") also
		// trips the charset rule, and "uses a reserved prefix" is the more useful message.
		lk := strings.ToLower(k)
		for _, p := range reservedTagPrefixes {
			if strings.HasPrefix(lk, p) {
				return fmt.Sprintf("tag key %q uses the reserved prefix %q", k, p)
			}
		}
		if !tagKeyRe.MatchString(k) {
			return fmt.Sprintf("tag key %q is invalid — use letters, digits, '.', '_' or '-', beginning and ending alphanumeric", k)
		}
		if len(v) > maxTagValueLen {
			return fmt.Sprintf("the value for tag %q is too long — a value is at most %d characters", k, maxTagValueLen)
		}
		if strings.ContainsFunc(v, isControlRune) {
			return fmt.Sprintf("the value for tag %q contains a control character", k)
		}
	}
	return ""
}

// isControlRune flags C0/C1 control characters (except common whitespace tab/newline, which a
// value may legitimately hold) so a tag value can't smuggle control bytes into metadata.
func isControlRune(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// tagAnnotationPatch builds the annotations sub-object of a JSON merge patch that REPLACES the tag
// set: every openinfra.dev/tag-* annotation currently on the object that is not in the new set is
// set to null (merge-patch delete), and every new tag is written under its prefixed key. Non-tag
// annotations (Crossplane's, anyone else's) are absent from the patch, so they are left intact.
func tagAnnotationPatch(cur, tags map[string]string) map[string]any {
	out := map[string]any{}
	for k := range cur {
		if !strings.HasPrefix(k, tagAnnotationPrefix) {
			continue
		}
		clean := strings.TrimPrefix(k, tagAnnotationPrefix)
		if _, keep := tags[clean]; !keep {
			out[k] = nil // merge-patch delete
		}
	}
	for k, v := range tags {
		out[tagAnnotationPrefix+k] = v
	}
	return out
}

// readAnnotations fetches just the object metadata annotations at an absolute CR path. ok is false
// when the object doesn't exist or can't be read, so the caller returns a clean 404 rather than
// patching a phantom.
func (a *authStore) readAnnotations(ctx context.Context, path string) (map[string]string, bool) {
	rc := a.rawREST()
	if rc == nil {
		return nil, false
	}
	raw, err := rc.Get().AbsPath(path).DoRaw(ctx)
	if err != nil {
		return nil, false
	}
	var obj struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil || obj.Metadata.Name == "" {
		return nil, false
	}
	if obj.Metadata.Annotations == nil {
		return map[string]string{}, true
	}
	return obj.Metadata.Annotations, true
}

type tagsReq struct {
	Tags map[string]string `json:"tags"`
}

// handleIAMTagsUpdate is the shared SET-tags handler for User / Role / Policy. It authorizes with
// the same "update" SAR as every other write to `resource`, validates the tag set, then merge-
// patches the CR's openinfra.dev/tag-* annotations to exactly the submitted set (add / change /
// remove). `noun` is the singular used in the 404 message; `absPath` names the CR collection.
func handleIAMTagsUpdate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger, resource, noun string, absPath func(string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if resource == "users" && name == "root" {
			// root is the break-glass account in a Secret, not a User — nothing to tag.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and is not managed here"})
			return
		}
		var in tagsReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		tags := cleanTags(in.Tags)
		if msg := validateTags(tags); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		// The same admins-only gate as the resource's other writes.
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", resource, auth.ns, name) {
			return
		}
		path := absPath(auth.ns) + "/" + name
		cur, ok := auth.readAnnotations(r.Context(), path)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such " + noun})
			return
		}
		patch := map[string]any{"metadata": map[string]any{"annotations": tagAnnotationPatch(cur, tags)}}
		if err := auth.patchCR(r.Context(), path, patch); err != nil {
			logger.Error("iam: update tags", "resource", resource, "name", name, "error", err.Error())
			writeIAMErr(w, err)
			return
		}
		logger.Info("iam: tags updated", "resource", resource, "name", name, "count", len(tags), "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}
