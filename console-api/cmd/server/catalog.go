package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// List the Iceberg catalog (schemas → tables) for the Query editor's Data tree when
// the Trino engine is selected. Read straight from the Iceberg REST catalog (the
// always-on metastore), NOT from Trino — so the tree works even while Trino is
// idle-stopped.

type catalogSchema struct {
	Schema string   `json:"schema"`
	Tables []string `json:"tables"`
}

func handleCatalogTables(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := getenv("ICEBERG_CATALOG_URL", "http://iceberg-rest.lakehouse.svc.cluster.local:8181")
		hc := &http.Client{Timeout: 8 * time.Second}

		var nsResp struct {
			Namespaces [][]string `json:"namespaces"`
		}
		if err := getJSON(hc, base+"/v1/namespaces", &nsResp); err != nil {
			// catalog unavailable → empty tree rather than an error
			writeJSON(w, http.StatusOK, []catalogSchema{})
			return
		}
		out := make([]catalogSchema, 0, len(nsResp.Namespaces))
		for _, ns := range nsResp.Namespaces {
			name := strings.Join(ns, ".")
			if name == "" {
				continue
			}
			tables := []string{}
			var tResp struct {
				Identifiers []struct {
					Name string `json:"name"`
				} `json:"identifiers"`
			}
			if getJSON(hc, base+"/v1/namespaces/"+name+"/tables", &tResp) == nil {
				for _, t := range tResp.Identifiers {
					tables = append(tables, t.Name)
				}
			}
			out = append(out, catalogSchema{Schema: name, Tables: tables})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func getJSON(hc *http.Client, url string, v any) error {
	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("catalog returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
