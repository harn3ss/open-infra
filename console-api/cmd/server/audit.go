package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
)

// The Audit view — open-infra's CloudTrail console.
//
// The authoritative "who did what" record is the Kubernetes API-server audit log, which
// carries impersonatedUser, so console, kubectl, Terraform and Argo actions are all
// attributed to a person. promtail ships it to Loki as job=k3s-audit (mutations + auth
// decisions; reads are dropped). This endpoint queries Loki and normalizes it.
//
// It ALSO queries the console's own structured log (namespace=open-infra-console, "iam:"
// lines). That matters because the BFF-native IAM handlers act as the ServiceAccount, so
// in the API-server audit log a "create user" shows the SA, not the person — but the BFF
// logged `by=<person>`. Merging both streams gives a complete, person-attributed trail.
//
// Admin-gated: the audit trail is every user's activity, so it is as sensitive as the IAM
// endpoints and reuses the same SubjectAccessReview gate.

// lokiBaseURL is the in-cluster Loki, overridable via LOKI_URL.
func lokiBaseURL() string {
	return strings.TrimRight(getenv("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100"), "/")
}

// auditEvent is one normalized entry the SPA renders.
type auditEvent struct {
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"`     // the person: impersonatedUser, or `by`
	Verb      string    `json:"verb"`      // create / update / patch / delete / …
	Resource  string    `json:"resource"`  // e.g. virtualmachines, users
	Namespace string    `json:"namespace"` // may be empty (cluster-scoped)
	Name      string    `json:"name"`
	Result    string    `json:"result"` // HTTP code, or "" for console-native
	Source    string    `json:"source"` // "k8s-audit" | "console"
}

type lokiValue struct {
	ts   time.Time
	line string
}

// queryLoki runs a LogQL range query and returns the raw (timestamp, line) pairs, newest
// first. Best-effort: any transport/parse failure returns an error the caller can degrade on.
func queryLoki(ctx context.Context, logql string, since time.Duration, limit int) ([]lokiValue, error) {
	end := time.Now()
	start := end.Add(-since)
	q := url.Values{}
	q.Set("query", logql)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "backward")
	endpoint := lokiBaseURL() + "/loki/api/v1/query_range?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return nil, fmt.Errorf("loki %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Data struct {
			Result []struct {
				Values [][2]string `json:"values"` // [ [ts_ns, line], … ]
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	var vals []lokiValue
	for _, r := range out.Data.Result {
		for _, v := range r.Values {
			ns, _ := strconv.ParseInt(v[0], 10, 64)
			vals = append(vals, lokiValue{ts: time.Unix(0, ns), line: v[1]})
		}
	}
	return vals, nil
}

// ── parsing the two streams into auditEvents ─────────────────────────────────────

// auditFromK8s parses one API-server audit JSON line. Returns ok=false for lines that
// aren't a usable mutation event.
func auditFromK8s(v lokiValue) (auditEvent, bool) {
	var e struct {
		Verb                     string `json:"verb"`
		Stage                    string `json:"stage"`
		RequestReceivedTimestamp string `json:"requestReceivedTimestamp"`
		User                     struct {
			Username string `json:"username"`
		} `json:"user"`
		Impersonated struct {
			Username string `json:"username"`
		} `json:"impersonatedUser"`
		ObjectRef struct {
			Resource  string `json:"resource"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"objectRef"`
		ResponseStatus struct {
			Code int `json:"code"`
		} `json:"responseStatus"`
	}
	if json.Unmarshal([]byte(v.line), &e) != nil {
		return auditEvent{}, false
	}
	if e.Verb == "" || e.ObjectRef.Resource == "" {
		return auditEvent{}, false
	}
	actor := e.Impersonated.Username
	if actor == "" {
		actor = e.User.Username
	}
	// Strip the openinfra: impersonation prefix so the UI shows the bare username.
	actor = strings.TrimPrefix(actor, "openinfra:")
	ts := v.ts
	if t, err := time.Parse(time.RFC3339Nano, e.RequestReceivedTimestamp); err == nil {
		ts = t
	}
	res := ""
	if e.ResponseStatus.Code != 0 {
		res = strconv.Itoa(e.ResponseStatus.Code)
	}
	return auditEvent{
		Time: ts, Actor: actor, Verb: e.Verb, Resource: e.ObjectRef.Resource,
		Namespace: e.ObjectRef.Namespace, Name: e.ObjectRef.Name, Result: res, Source: "k8s-audit",
	}, true
}

// auditFromConsole parses a BFF "iam:" structured-log line, e.g.
// {"time":"…","msg":"iam: user created","user":"alice","by":"root"}.
//
// The IAM handlers log the target under a key that matches the kind — "user", "group",
// "policy" or "role" — so we read all of them and take whichever is set. Reading only
// "user" would leave every group/policy/role event without its target name.
func auditFromConsole(v lokiValue) (auditEvent, bool) {
	var e struct {
		Time   string `json:"time"`
		Msg    string `json:"msg"`
		By     string `json:"by"`
		User   string `json:"user"`
		Group  string `json:"group"`
		Policy string `json:"policy"`
		Role   string `json:"role"`
	}
	if json.Unmarshal([]byte(v.line), &e) != nil {
		return auditEvent{}, false
	}
	if !strings.HasPrefix(e.Msg, "iam:") || e.By == "" {
		return auditEvent{}, false
	}
	// "iam: user created" → resource "user", verb "created".
	fields := strings.Fields(strings.TrimPrefix(e.Msg, "iam:"))
	resource, verb := "", ""
	if len(fields) >= 2 {
		resource, verb = fields[0], strings.Join(fields[1:], " ")
	}
	name := firstNonEmpty(e.User, e.Group, e.Policy, e.Role)
	ts := v.ts
	if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
		ts = t
	}
	return auditEvent{
		Time: ts, Actor: e.By, Verb: verb, Resource: resource, Name: name,
		Namespace: "open-infra-console", Source: "console",
	}, true
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// handleAudit serves the merged, person-attributed audit trail.
func handleAudit(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Same admin gate as IAM management — this is everyone's activity.
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}

		since := 24 * time.Hour
		if s := r.URL.Query().Get("since"); s != "" {
			if d, err := time.ParseDuration(s); err == nil && d > 0 && d <= 30*24*time.Hour {
				since = d
			}
		}
		limit := 200
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		actorFilter := strings.TrimSpace(r.URL.Query().Get("actor"))
		resourceFilter := strings.TrimSpace(r.URL.Query().Get("resource"))

		// Text pre-filter in LogQL narrows the fetch; exact filtering happens in Go.
		auditQ := `{job="k3s-audit"}`
		if actorFilter != "" {
			auditQ += fmt.Sprintf(" |= %q", actorFilter)
		}
		consoleQ := `{namespace="open-infra-console"} |= "iam:"`
		if actorFilter != "" {
			consoleQ += fmt.Sprintf(" |= %q", actorFilter)
		}

		var events []auditEvent
		if vals, err := queryLoki(r.Context(), auditQ, since, limit); err != nil {
			// Loki down / not deployed → degrade to whatever the other source gives,
			// and tell the SPA so it can show a banner rather than an empty table.
			logger.Warn("audit: k8s-audit query failed", "error", err.Error())
			w.Header().Set("X-Audit-Partial", "k8s-audit unavailable")
		} else {
			for _, v := range vals {
				if e, ok := auditFromK8s(v); ok {
					events = append(events, e)
				}
			}
		}
		if vals, err := queryLoki(r.Context(), consoleQ, since, limit); err == nil {
			for _, v := range vals {
				if e, ok := auditFromConsole(v); ok {
					events = append(events, e)
				}
			}
		}

		// Post-filter and sort newest-first.
		filtered := events[:0]
		for _, e := range events {
			if actorFilter != "" && !strings.Contains(e.Actor, actorFilter) {
				continue
			}
			if resourceFilter != "" && !strings.Contains(e.Resource, resourceFilter) {
				continue
			}
			filtered = append(filtered, e)
		}
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Time.After(filtered[j].Time) })
		if len(filtered) > limit {
			filtered = filtered[:limit]
		}
		writeJSON(w, http.StatusOK, filtered)
	}
}
