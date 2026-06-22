package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// --- DMS sync trigger + status (the headless Airbyte engine) ----------------
//
// A kind: Migration is backed by an Airbyte connection (created by Crossplane).
// The console drives that engine without ever exposing Airbyte: it reads the
// connection id from the Migration's <name>-outputs secret (written by the
// composition) and the instance-admin client creds from airbyte-auth-secrets,
// exchanges them for a short-lived token, and triggers/polls a sync via the
// public API. The browser never sees Airbyte.

func airbyteBase() string {
	return strings.TrimRight(
		getenv("AIRBYTE_API_URL", "http://airbyte-airbyte-server-svc.airbyte:8001/api/public/v1"),
		"/",
	)
}

// airbyteToken exchanges the instance-admin client credentials for a bearer token.
func airbyteToken(ctx context.Context, cs kubernetes.Interface) (string, error) {
	ns := getenv("AIRBYTE_SECRET_NAMESPACE", "airbyte")
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, getenv("AIRBYTE_AUTH_SECRET", "airbyte-auth-secrets"), metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"client_id":     string(sec.Data["instance-admin-client-id"]),
		"client_secret": string(sec.Data["instance-admin-client-secret"]),
		"grant-type":    "client_credentials", // hyphen is intentional (Airbyte's API)
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, airbyteBase()+"/applications/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("token request failed (status %d)", resp.StatusCode)
	}
	return tok.AccessToken, nil
}

// migrationConnectionID reads the Airbyte connection id from the Migration's
// outputs secret (written by the composition's writeConnectionSecretToRef).
func migrationConnectionID(ctx context.Context, cs kubernetes.Interface, ns, name string) (string, error) {
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, name+"-outputs", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("no connection yet")
	}
	id := strings.TrimSpace(string(sec.Data["connection_id"]))
	if id == "" {
		return "", fmt.Errorf("no connection yet")
	}
	return id, nil
}

// handleMigrationSync triggers a sync job for a Migration's Airbyte connection.
func handleMigrationSync(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		connID, err := migrationConnectionID(r.Context(), cs, ns, name)
		if err != nil {
			writeError(w, http.StatusConflict, "migration is still provisioning")
			return
		}
		token, err := airbyteToken(r.Context(), cs)
		if err != nil {
			logger.Error("airbyte token", slog.String("error", err.Error()))
			writeError(w, http.StatusBadGateway, "DMS engine unavailable")
			return
		}
		body, _ := json.Marshal(map[string]string{"connectionId": connID, "jobType": "sync"})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, airbyteBase()+"/jobs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not trigger sync")
			return
		}
		defer resp.Body.Close()
		var job map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&job)
		if resp.StatusCode >= 300 {
			writeError(w, http.StatusBadGateway, "sync rejected by the DMS engine")
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	}
}

// handleMigrationSyncStatus returns recent sync jobs for a Migration's connection.
func handleMigrationSyncStatus(cs kubernetes.Interface, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := chi.URLParam(r, "namespace")
		name := chi.URLParam(r, "name")
		connID, err := migrationConnectionID(r.Context(), cs, ns, name)
		if err != nil {
			// Not provisioned yet — report empty rather than an error.
			writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
			return
		}
		token, err := airbyteToken(r.Context(), cs)
		if err != nil {
			writeError(w, http.StatusBadGateway, "DMS engine unavailable")
			return
		}
		u := fmt.Sprintf("%s/jobs?connectionId=%s&limit=10", airbyteBase(), connID)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeError(w, http.StatusBadGateway, "could not read sync status")
			return
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if out == nil {
			out = map[string]any{}
		}
		out["connectionId"] = connID
		writeJSON(w, http.StatusOK, out)
	}
}
