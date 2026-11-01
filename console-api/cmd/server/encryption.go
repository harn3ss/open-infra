package main

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The Encryption view — customer-owned keys (kind: EncryptionKey, Vault Transit).
//
// The composition mirrors each EncryptionKey's spec to a ConfigMap (openinfra-enckey-<namespace>.<name>),
// and the reconciler writes the live Vault state to a second ConfigMap
// (openinfra-enckey-state-<namespace>.<name>); both carry the label openinfra.dev/enckey=<name> and
// record the key's namespace + name in their data. (A key created before namespacing keeps its
// bare-name ConfigMaps.) This endpoint merges them per namespace + name so the console can show each
// key, its type/rotation policy, and whether its Transit key is actually provisioned — without the
// console needing Vault access (it never sees key material). Admin-gated.

type encKeyView struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace,omitempty"` // the EncryptionKey's namespace ("" = a record without one)
	Description  string `json:"description"`
	KeyType      string `json:"keyType"`
	RotationDays int    `json:"rotationDays"`
	VaultKeyPath string `json:"vaultKeyPath"`
	// Live state from the reconciler (absent until it has run against Vault):
	Provisioned   bool   `json:"provisioned"`
	LatestVersion int    `json:"latestVersion"`
	LastRotated   string `json:"lastRotated,omitempty"`
	LastChecked   string `json:"lastChecked,omitempty"`
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func handleEncryptionKeys(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		cms, err := cs.CoreV1().ConfigMaps(auth.ns).List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/enckey"})
		if err != nil {
			logger.Warn("encryption: list key configmaps", slog.String("error", err.Error()))
			writeJSON(w, http.StatusOK, []encKeyView{})
			return
		}

		keys := map[string]*encKeyView{}
		for i := range cms.Items {
			cm := &cms.Items[i]
			name := cm.Labels["openinfra.dev/enckey"]
			if name == "" {
				continue
			}
			d := cm.Data
			if n := d["name"]; n != "" {
				name = n
			}
			id := recordKey(d["namespace"], name)
			if keys[id] == nil {
				keys[id] = &encKeyView{Name: name, Namespace: d["namespace"]}
			}
			k := keys[id]
			// The spec mirror carries description/rotationDays; the state carries exists/latestVersion.
			if v, ok := d["description"]; ok {
				k.Description = v
			}
			if v, ok := d["keyType"]; ok {
				k.KeyType = v
			}
			if v, ok := d["rotationDays"]; ok {
				k.RotationDays = atoiOr(v, 0)
			}
			if v, ok := d["vaultKeyPath"]; ok {
				k.VaultKeyPath = v
			}
			if d["exists"] == "true" {
				k.Provisioned = true
			}
			if v, ok := d["latestVersion"]; ok {
				k.LatestVersion = atoiOr(v, 0)
			}
			if v := d["lastRotatedEpoch"]; v != "" {
				if sec := atoiOr(v, 0); sec > 0 {
					k.LastRotated = time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
				}
			}
			if v, ok := d["lastChecked"]; ok {
				k.LastChecked = v
			}
		}

		out := make([]encKeyView, 0, len(keys))
		for _, k := range keys {
			out = append(out, *k)
		}
		sort.Slice(out, func(i, j int) bool {
			return recordKey(out[i].Namespace, out[i].Name) < recordKey(out[j].Namespace, out[j].Name)
		})
		writeJSON(w, http.StatusOK, out)
	}
}

// A crypto-erase request (kind: Destruction) and its outcome, merged from the spec-mirror + state
// ConfigMaps the destroyer maintains.
type destructionView struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace,omitempty"` // the Destruction's namespace ("" = a record without one)
	EncryptionKey string `json:"encryptionKey"`
	Reason        string `json:"reason"`
	Phase         string `json:"phase"` // Pending | InProgress | Refused | Destroyed | Error
	Message       string `json:"message,omitempty"`
	Certificate   string `json:"certificate,omitempty"` // WORM object path of the destruction certificate
	CertSha256    string `json:"certSha256,omitempty"`  // sha256 of the certificate (anchor to verify the locked original)
	DestroyedAt   string `json:"destroyedAt,omitempty"`
}

func handleDestructions(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		cms, err := cs.CoreV1().ConfigMaps(auth.ns).List(ctx, metav1.ListOptions{LabelSelector: "openinfra.dev/destruction"})
		if err != nil {
			logger.Warn("encryption: list destruction configmaps", slog.String("error", err.Error()))
			writeJSON(w, http.StatusOK, []destructionView{})
			return
		}
		views := map[string]*destructionView{}
		for i := range cms.Items {
			cm := &cms.Items[i]
			name := cm.Labels["openinfra.dev/destruction"]
			if name == "" {
				continue
			}
			d := cm.Data
			id := recordKey(d["namespace"], name)
			if views[id] == nil {
				views[id] = &destructionView{Name: name, Namespace: d["namespace"], Phase: "Pending"}
			}
			v := views[id]
			if s, ok := d["encryptionKey"]; ok && s != "" {
				v.EncryptionKey = s
			}
			if s, ok := d["reason"]; ok && s != "" {
				v.Reason = s
			}
			if s, ok := d["phase"]; ok && s != "" {
				v.Phase = s
			}
			if s, ok := d["message"]; ok && s != "" {
				v.Message = s
			}
			if s, ok := d["certificate"]; ok && s != "" {
				v.Certificate = s
			}
			if s, ok := d["certSha256"]; ok && s != "" {
				v.CertSha256 = s
			}
			if s, ok := d["destroyedAt"]; ok && s != "" {
				v.DestroyedAt = s
			}
		}
		out := make([]destructionView, 0, len(views))
		for _, v := range views {
			out = append(out, *v)
		}
		sort.Slice(out, func(i, j int) bool {
			return recordKey(out[i].Namespace, out[i].Name) < recordKey(out[j].Namespace, out[j].Name)
		})
		writeJSON(w, http.StatusOK, out)
	}
}

// recordKey is the identity a mirrored record merges under: <namespace>/<name>, or the bare name for a
// record written before records carried their namespace.
func recordKey(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}
