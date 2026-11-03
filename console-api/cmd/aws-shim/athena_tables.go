package main

// Which tables an Athena query touches, and whether the caller may touch them.
//
// The SQL runs on Trino, which authenticates nobody: the shim is the only gate. On AWS a query needs
// glue:GetTable on every table it reads (and the data's S3 permissions), so here too each table is
// authorized before the query runs. The tables come from Trino's own planner — EXPLAIN (TYPE IO,
// FORMAT JSON) lists every table a statement reads and the one it writes — never from parsing the SQL,
// which a CTE, a view or a quoted name would fool. It is fail-closed: a statement Trino cannot plan that
// way (DDL, SHOW, a syntax error) is authorized as touching any table (Table::*), so an assumed role
// needs a grant on every table to run one, and a User's Deny on Table::* refuses it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// athenaTable is one table a query reads or writes, as Trino names it.
type athenaTable struct {
	Catalog, Schema, Table string
	Write                  bool
}

// athenaIOPlan is the part of EXPLAIN (TYPE IO, FORMAT JSON) the check reads.
type athenaIOPlan struct {
	Inputs []struct {
		Table struct {
			Catalog     string `json:"catalog"`
			SchemaTable struct {
				Schema string `json:"schema"`
				Table  string `json:"table"`
			} `json:"schemaTable"`
		} `json:"table"`
	} `json:"inputTableColumnInfos"`
	Output *struct {
		Catalog     string `json:"catalog"`
		SchemaTable struct {
			Schema string `json:"schema"`
			Table  string `json:"table"`
		} `json:"schemaTable"`
	} `json:"outputTable"`
}

// parseIOPlan reads the tables from an EXPLAIN (TYPE IO, FORMAT JSON) result.
func parseIOPlan(doc string) ([]athenaTable, error) {
	var p athenaIOPlan
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return nil, fmt.Errorf("unreadable IO plan: %w", err)
	}
	var out []athenaTable
	for _, in := range p.Inputs {
		out = append(out, athenaTable{Catalog: in.Table.Catalog, Schema: in.Table.SchemaTable.Schema, Table: in.Table.SchemaTable.Table})
	}
	if p.Output != nil {
		out = append(out, athenaTable{Catalog: p.Output.Catalog, Schema: p.Output.SchemaTable.Schema, Table: p.Output.SchemaTable.Table, Write: true})
	}
	return out, nil
}

// explainIO asks Trino for the statement's IO plan. An error means the statement could not be planned.
func explainIO(ctx context.Context, client *trinoClient, sql, user, catalog, schema string) ([]athenaTable, error) {
	q, err := client.submit(ctx, "EXPLAIN (TYPE IO, FORMAT JSON) "+sql, user, catalog, schema)
	if err != nil {
		return nil, err
	}
	var doc strings.Builder
	page := q.page()
	for {
		if page.ErrMsg != "" {
			return nil, errors.New(page.ErrMsg)
		}
		for _, row := range page.Rows {
			if len(row) > 0 {
				s, _ := row[0].(string)
				doc.WriteString(s)
			}
		}
		if page.NextURI == "" {
			break
		}
		if page, err = client.advance(ctx, page.NextURI, user); err != nil {
			return nil, err
		}
	}
	return parseIOPlan(doc.String())
}

// athenaTableChecks are the (Glue action, Table resource) pairs a query needs: glue:GetTable on each table
// it reads, glue:UpdateTable on the one it writes, the table named <schema>/<table> as the Glue front door
// names it. A table outside the fronted catalog, or a statement with no plan (tables == nil), is checked
// on Table::* — any table.
func athenaTableChecks(tables []athenaTable, planned bool, catalog string) [][2]string {
	if !planned {
		return [][2]string{{"glue:GetTable", anyResource}}
	}
	var out [][2]string
	seen := map[[2]string]bool{}
	for _, t := range tables {
		id := t.Schema + "/" + t.Table
		if t.Catalog != catalog || t.Schema == "" || t.Table == "" {
			id = anyResource
		}
		action := "glue:GetTable"
		if t.Write {
			action = "glue:UpdateTable"
		}
		if c := [2]string{action, id}; !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
