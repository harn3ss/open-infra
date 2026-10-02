// A tiny client for the platform's Trino coordinator `/v1/statement` REST API (polyhedron#179).
//
// The Athena doorway does NOT re-implement a SQL engine: an Athena query IS a Trino query over the
// `iceberg` catalog, so rather than embed an executor we submit the SQL to the real coordinator
// (trino.lakehouse) over its standard REST protocol — the same engine DataFlow and the Catalog kind
// already use. This client is deliberately dependency-free (net/http + encoding/json), bounds every call
// by the caller's context plus its own timeout, and exposes exactly the three verbs the async runner
// needs: submit (POST the SQL), advance (follow a nextUri), and cancel (DELETE the running query).
//
// Trino drives a query as a chain of pages: the POST returns the first page, and each page carries a
// `nextUri` to GET for the next until one has none (terminal). Columns appear once mid-stream; rows
// accrue a page at a time; an `error` object anywhere means the query FAILED. The SQL is sent VERBATIM —
// the doorway does no Athena→Trino dialect rewriting, so Athena-only syntax that Trino cannot parse comes
// back as a FAILED query carrying Trino's own error, never a silent divergence.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// the X-Trino-Source tag every query from this doorway carries (so Trino's UI/audit attributes it).
const trinoSource = "openinfra-athena"

// trinoColumn is one result column (name + Trino SQL type), carried through to Athena's ColumnInfo.
type trinoColumn struct {
	Name string
	Type string
}

// trinoPage is one response page from /v1/statement (the POST and every nextUri GET share this shape):
// the columns (present once, mid-stream), the rows on THIS page, the query state, the next page's URI
// ("" when terminal), and a non-empty ErrMsg when Trino reported a query error.
type trinoPage struct {
	Columns []trinoColumn
	Rows    [][]any
	State   string
	NextURI string
	ErrMsg  string
}

// trinoQuery is the handle submit() returns: the coordinator-assigned query id plus the FIRST page
// (which may already carry columns/rows/state). The runner follows nextURI() to completion.
type trinoQuery struct {
	id    string
	first *trinoPage
}

func (q *trinoQuery) nextURI() string  { return q.first.NextURI }
func (q *trinoQuery) queryID() string  { return q.id }
func (q *trinoQuery) page() *trinoPage { return q.first }

// trinoResponse is the raw /v1/statement JSON. Both the POST and every poll return this exact shape.
type trinoResponse struct {
	ID      string `json:"id"`
	InfoURI string `json:"infoUri"`
	NextURI string `json:"nextUri"`
	Columns []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"columns"`
	Data  [][]any `json:"data"`
	Stats struct {
		State string `json:"state"`
	} `json:"stats"`
	Error *struct {
		Message   string `json:"message"`
		ErrorName string `json:"errorName"`
	} `json:"error"`
}

// page projects the raw response into the trinoPage the runner consumes.
func (tr *trinoResponse) page() *trinoPage {
	p := &trinoPage{State: tr.Stats.State, NextURI: tr.NextURI, Rows: tr.Data}
	for _, c := range tr.Columns {
		p.Columns = append(p.Columns, trinoColumn{Name: c.Name, Type: c.Type})
	}
	if tr.Error != nil {
		p.ErrMsg = tr.Error.Message
		if p.ErrMsg == "" {
			p.ErrMsg = tr.Error.ErrorName
		}
	}
	return p
}

// trinoClient speaks the /v1/statement REST protocol against one coordinator base URL. Dependency-free;
// every call is bounded by the caller's context and the client's own timeout. The coordinator runs
// in-cluster with no auth — the identity travels only as the X-Trino-User label (for Trino's own audit).
type trinoClient struct {
	base string // coordinator base URL, no trailing slash (e.g. http://trino.lakehouse.svc.cluster.local:8080)
	hc   *http.Client
}

func newTrinoClient(base string) *trinoClient {
	return &trinoClient{
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// submit POSTs the raw SQL as the request body (text/plain) with Trino's routing headers and returns the
// first page. The SQL is sent VERBATIM (no dialect rewriting). An omitted schema sends no X-Trino-Schema.
func (c *trinoClient) submit(ctx context.Context, sql, user, catalog, schema string) (*trinoQuery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/statement", strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Trino-User", trinoUser(user))
	if catalog != "" {
		req.Header.Set("X-Trino-Catalog", catalog)
	}
	if schema != "" {
		req.Header.Set("X-Trino-Schema", schema)
	}
	req.Header.Set("X-Trino-Source", trinoSource)
	tr, err := c.readResponse(ctx, req, "submit")
	if err != nil {
		return nil, err
	}
	return &trinoQuery{id: tr.ID, first: tr.page()}, nil
}

// advance follows a nextUri with a GET (no body), carrying the same X-Trino-User, and returns that page.
func (c *trinoClient) advance(ctx context.Context, uri, user string) (*trinoPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Trino-User", trinoUser(user))
	tr, err := c.readResponse(ctx, req, "advance")
	if err != nil {
		return nil, err
	}
	return tr.page(), nil
}

// cancel DELETEs the current nextUri, which tells Trino to abort the running query. A missing/empty uri is
// a no-op, and any 2xx (Trino answers 204) is success — a best-effort stop, never a hard failure path.
func (c *trinoClient) cancel(ctx context.Context, uri, user string) error {
	if uri == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Trino-User", trinoUser(user))
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return &trinoStatusError{op: "cancel", status: resp.StatusCode}
}

// readResponse issues a request and decodes the /v1/statement JSON, bounding the body so a pathological
// page can never exhaust memory. A non-200 is an honest status error (the runner fails the exec), never
// mistaken for a clean page.
func (c *trinoClient) readResponse(_ context.Context, req *http.Request, op string) (*trinoResponse, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, &trinoStatusError{op: op, status: resp.StatusCode}
	}
	var tr trinoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// trinoUser returns the X-Trino-User label for a request, falling back to the doorway's own source name
// when no principal is resolved (so the header is never empty — Trino rejects an empty user).
func trinoUser(user string) string {
	if strings.TrimSpace(user) == "" {
		return trinoSource
	}
	return user
}

// trinoStatusError is an unexpected (non-200) coordinator status — surfaced so the runner marks the exec
// FAILED with a clear reason rather than mistaking it for an empty result.
type trinoStatusError struct {
	op     string
	status int
}

func (e *trinoStatusError) Error() string {
	return "trino " + e.op + ": unexpected status " + itoa(e.status)
}
