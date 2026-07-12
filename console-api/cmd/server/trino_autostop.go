package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Trino idle-stop: scale the Trino coordinator to 0 when no engine=trino query has
// run recently, and back to 1 the moment one appears — so the "Catalog" engine costs
// nothing at rest (Redshift-Serverless-style). The engine=trino query runner waits
// for Trino to become ready, so a query submitted while it's down just takes the
// cold-start hit once. DuckDB queries are unaffected (they never touch Trino).

const (
	trinoNamespace  = "lakehouse"
	trinoDeployment = "trino"
)

func startTrinoAutostop(host *url.URL, transport http.RoundTripper, cs kubernetes.Interface, logger *slog.Logger) {
	if getenv("TRINO_AUTOSTOP", "on") != "on" {
		return
	}
	idle := 10 * time.Minute
	if d, err := time.ParseDuration(getenv("TRINO_IDLE", "")); err == nil && d >= time.Minute {
		idle = d
	}
	go func() {
		time.Sleep(45 * time.Second) // let the platform settle on boot
		for {
			trinoAutostopOnce(host, transport, cs, idle, logger)
			time.Sleep(20 * time.Second)
		}
	}()
	logger.Info("trino autostop: started", slog.Duration("idle", idle))
}

func trinoAutostopOnce(host *url.URL, transport http.RoundTripper, cs kubernetes.Interface, idle time.Duration, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	newest, err := newestTrinoQueryTime(ctx, host, transport)
	if err != nil {
		return // never scale on an API error — only against a trustworthy set
	}
	var want int32 = 0
	if !newest.IsZero() && time.Since(newest) < idle {
		want = 1
	}

	dep, err := cs.AppsV1().Deployments(trinoNamespace).Get(ctx, trinoDeployment, metav1.GetOptions{})
	if err != nil {
		return // Trino not installed / not reachable — nothing to manage
	}
	var cur int32 = 1
	if dep.Spec.Replicas != nil {
		cur = *dep.Spec.Replicas
	}
	if cur == want {
		return
	}
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, want))
	if _, err := cs.AppsV1().Deployments(trinoNamespace).Patch(ctx, trinoDeployment, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err == nil {
		logger.Info("trino autostop: scaled", slog.Int("replicas", int(want)))
	}
}

// newestTrinoQueryTime returns the creationTimestamp of the most recent
// engine=trino Query across all namespaces (zero time if there are none).
func newestTrinoQueryTime(ctx context.Context, host *url.URL, transport http.RoundTripper) (time.Time, error) {
	u := *host
	u.Path = "/apis/openinfra.dev/v1/queries"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, &sgStatusError{resp.StatusCode}
	}
	var list struct {
		Items []struct {
			Metadata struct {
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Spec struct {
				Engine string `json:"engine"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, it := range list.Items {
		if it.Spec.Engine != "trino" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, it.Metadata.CreationTimestamp); err == nil && t.After(newest) {
			newest = t
		}
	}
	return newest, nil
}
