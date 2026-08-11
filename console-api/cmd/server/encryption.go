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
// The composition mirrors each EncryptionKey's spec to a ConfigMap (openinfra-enckey-<name>), and
// the reconciler writes the live Vault state to a second ConfigMap (openinfra-enckey-state-<name>);
// both carry the label openinfra.dev/enckey=<name>. This endpoint merges them so the console can
// show each key, its type/rotation policy, and whether its Transit key is actually provisioned —
// without the console needing Vault access (it never sees key material). Admin-gated.

type encKeyView struct {
	Name         string `json:"name"`
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
		get := func(name string) *encKeyView {
			if keys[name] == nil {
				keys[name] = &encKeyView{Name: name}
			}
			return keys[name]
		}
		for i := range cms.Items {
			cm := &cms.Items[i]
			name := cm.Labels["openinfra.dev/enckey"]
			if name == "" {
				continue
			}
			k := get(name)
			d := cm.Data
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
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		writeJSON(w, http.StatusOK, out)
	}
}
