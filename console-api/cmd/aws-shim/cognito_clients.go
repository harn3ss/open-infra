// Cognito app-client reads: DescribeUserPoolClient and ListUserPoolClients over the clients
// CreateUserPoolClient keeps (cognito_clients), in the AWS JSON 1.1 shapes the CLI and SDKs parse. Both are
// control-plane operations of the pool they name, so dispatch authorizes them as DescribeUserPool is (get on
// the coarse gate, cognito-idp:<Op> on UserPool::<pool>). A client has no secret here (CreateUserPoolClient
// generates none), so none is answered.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// cognitoListClientsMax is ListUserPoolClients' MaxResults ceiling (AWS: 1–60).
const cognitoListClientsMax = 60

func (h *cognitoHandler) describeUserPoolClient(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	pool := asString(body["UserPoolId"])
	if _, ok := h.mustPool(ctx, w, requestID, pool); !ok {
		return
	}
	id := asString(body["ClientId"])
	if id == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "ClientId is required.")
		return
	}
	c, ok, err := h.store.getClient(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	// A client of another pool is not one of this pool's (the pool is what the caller was authorized on).
	if !ok || c.PoolID != pool {
		writeCognitoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "User pool client "+id+" does not exist.")
		return
	}
	out := map[string]any{"ClientId": c.ID, "UserPoolId": c.PoolID, "ClientName": c.Name, "ExplicitAuthFlows": c.AuthFlows}
	if !c.Created.IsZero() {
		out["CreationDate"] = cognitoEpoch(c.Created)
		out["LastModifiedDate"] = cognitoEpoch(c.Created)
	}
	writeCognitoJSON(w, requestID, map[string]any{"UserPoolClient": out})
}

func (h *cognitoHandler) listUserPoolClients(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	pool := asString(body["UserPoolId"])
	if _, ok := h.mustPool(ctx, w, requestID, pool); !ok {
		return
	}
	limit := cognitoListClientsMax
	if v, ok := body["MaxResults"].(float64); ok {
		if v < 1 || v > cognitoListClientsMax {
			writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "MaxResults must be between 1 and 60.")
			return
		}
		limit = int(v)
	}
	after := asString(body["NextToken"])
	clients, more, err := h.store.listClients(ctx, pool, after, limit)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		items = append(items, map[string]any{"ClientId": c.ID, "UserPoolId": c.PoolID, "ClientName": c.Name})
	}
	out := map[string]any{"UserPoolClients": items}
	if more && len(clients) > 0 {
		out["NextToken"] = clients[len(clients)-1].ID
	}
	writeCognitoJSON(w, requestID, out)
}

// cognitoEpoch is Cognito's timestamp form: epoch seconds (the SDKs read a JSON number).
func cognitoEpoch(t time.Time) json.Number {
	return json.Number(strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64))
}

// listClients is a pool's clients in client-id order after the id `after` (a ListUserPoolClients
// NextToken), at most limit of them, and whether more follow.
func (s *cognitoStore) listClients(ctx context.Context, poolID, after string, limit int) ([]cognitoClient, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, pool_id, name, auth_flows, created FROM cognito_clients
		WHERE pool_id=$1 AND client_id > $2 ORDER BY client_id LIMIT $3`, poolID, after, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []cognitoClient
	for rows.Next() {
		var c cognitoClient
		var af []byte
		if err := rows.Scan(&c.ID, &c.PoolID, &c.Name, &af, &c.Created); err != nil {
			return nil, false, err
		}
		_ = json.Unmarshal(af, &c.AuthFlows)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
