// CloudFormation calls signed with an instance identity (CFN_V1), and the GET + JSON form of the
// query API that aws-cfn-bootstrap uses.
//
// cfn-init, cfn-signal and cfn-hup run without credentials sign their calls `Authorization: CFN_V1
// <base64 identity document>:<signature>` (aws-cfn-bootstrap's CFNSigner) with the document their instance
// metadata serves. The platform signs those documents (instance_identity.go), so here the signature is
// checked against the platform's key, the document must be unexpired and this account's, and the caller
// is then the instance it names, with exactly the authority CFN_V1 has on AWS:
//   - SignalResource, DescribeStackResource and DescribeStackResources only;
//   - on the stack that launched the instance only. The stack record (the shim's own, which tenants cannot
//     write) must list a kind: VirtualMachine whose composite is bound to it and whose instance id is the
//     document's. A copied document of another instance, a stack the instance is not part of, a VM
//     deleted and re-created under the same name (a new composite, so a new instance id) and a VM that is
//     not running are all refused, with one message for "no such stack" and "not your stack".
//
// aws-cfn-bootstrap sends its calls with GET (the parameters in the query string) and ContentType=JSON, and
// reads JSON back (StackResourceDetail with an epoch LastUpdatedTimestamp, errors as {"Error": {...}}).
// Both are served for those three actions, on this path and on the SigV4 one (`cfn-signal --role`).
package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
)

// cfnJSONActions are the actions answered in JSON when the call asks for it (aws-cfn-bootstrap's).
var cfnJSONActions = map[string]bool{"SignalResource": true, "DescribeStackResource": true, "DescribeStackResources": true}

// queryParamsAsForm makes a GET call's query-string parameters the form the handlers read (PostForm), as
// the Query protocol allows either. The query is part of what a SigV4 signature covers.
func queryParamsAsForm(r *http.Request) {
	if r.Method != http.MethodGet || len(r.PostForm) > 0 {
		return
	}
	if r.PostForm == nil {
		r.PostForm = map[string][]string{}
	}
	for k, v := range r.URL.Query() {
		r.PostForm[k] = append([]string(nil), v...)
	}
}

// wantsQueryJSON reports whether a call asks for a JSON answer (ContentType=JSON) for an action that has one.
func wantsQueryJSON(r *http.Request) bool {
	return strings.EqualFold(r.PostFormValue("ContentType"), "JSON") && cfnJSONActions[r.PostFormValue("Action")]
}

// queryCapture buffers a handler's XML answer so it can be re-written as JSON.
type queryCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newQueryCapture() *queryCapture {
	return &queryCapture{header: http.Header{}, status: http.StatusOK}
}

func (c *queryCapture) Header() http.Header         { return c.header }
func (c *queryCapture) WriteHeader(status int)      { c.status = status }
func (c *queryCapture) Write(b []byte) (int, error) { return c.body.Write(b) }

// flushJSON writes the captured answer to w in JSON, or unchanged when it is not one of the shapes known.
func (c *queryCapture) flushJSON(w http.ResponseWriter) {
	out, ok := queryXMLToJSON(c.body.Bytes())
	for k, v := range c.header {
		if ok && strings.EqualFold(k, "Content-Type") {
			continue
		}
		w.Header()[k] = v
	}
	if !ok {
		w.WriteHeader(c.status)
		_, _ = w.Write(c.body.Bytes())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.status)
	_, _ = w.Write(out)
}

// queryXMLToJSON re-writes an error or a SignalResource / DescribeStackResource / DescribeStackResources
// answer in the Query protocol's JSON form.
func queryXMLToJSON(body []byte) ([]byte, bool) {
	root := ""
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		if se, ok := tok.(xml.StartElement); ok {
			root = se.Name.Local
			break
		}
	}
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	meta := func(id string) map[string]any { return map[string]any{"RequestId": id} }
	var v any
	switch root {
	case "ErrorResponse":
		var e errorResponse
		if xml.Unmarshal(body, &e) != nil {
			return nil, false
		}
		v = map[string]any{"Error": map[string]any{"Code": e.Error.Code, "Message": e.Error.Message, "Type": e.Error.Type}, "RequestId": e.RequestId}
	case "SignalResourceResponse":
		var x struct {
			RequestID string `xml:"ResponseMetadata>RequestId"`
		}
		if xml.Unmarshal(body, &x) != nil {
			return nil, false
		}
		v = map[string]any{"SignalResourceResponse": map[string]any{"ResponseMetadata": meta(x.RequestID)}}
	case "DescribeStackResourceResponse":
		var x struct {
			D struct {
				StackName, StackId, LogicalResourceId, PhysicalResourceId, ResourceType string
				LastUpdatedTimestamp, ResourceStatus, ResourceStatusReason, Metadata    string
				Description                                                             string
			} `xml:"DescribeStackResourceResult>StackResourceDetail"`
			RequestID string `xml:"ResponseMetadata>RequestId"`
		}
		if xml.Unmarshal(body, &x) != nil {
			return nil, false
		}
		d := x.D
		v = map[string]any{"DescribeStackResourceResponse": map[string]any{
			"DescribeStackResourceResult": map[string]any{"StackResourceDetail": map[string]any{
				"StackName": d.StackName, "StackId": d.StackId, "LogicalResourceId": d.LogicalResourceId,
				"PhysicalResourceId": nilIfEmpty(d.PhysicalResourceId), "ResourceType": d.ResourceType,
				"LastUpdatedTimestamp": rfc3339Epoch(d.LastUpdatedTimestamp), "ResourceStatus": d.ResourceStatus,
				"ResourceStatusReason": nilIfEmpty(d.ResourceStatusReason), "Metadata": nilIfEmpty(d.Metadata),
				"Description": nilIfEmpty(d.Description),
			}},
			"ResponseMetadata": meta(x.RequestID),
		}}
	case "DescribeStackResourcesResponse":
		var x struct {
			M []struct {
				StackName, StackId, LogicalResourceId, PhysicalResourceId, ResourceType string
				ResourceStatus, ResourceStatusReason, Timestamp                         string
			} `xml:"DescribeStackResourcesResult>StackResources>member"`
			RequestID string `xml:"ResponseMetadata>RequestId"`
		}
		if xml.Unmarshal(body, &x) != nil {
			return nil, false
		}
		list := make([]map[string]any, 0, len(x.M))
		for _, m := range x.M {
			list = append(list, map[string]any{
				"StackName": m.StackName, "StackId": m.StackId, "LogicalResourceId": m.LogicalResourceId,
				"PhysicalResourceId": nilIfEmpty(m.PhysicalResourceId), "ResourceType": m.ResourceType,
				"ResourceStatus": m.ResourceStatus, "ResourceStatusReason": nilIfEmpty(m.ResourceStatusReason),
				"Timestamp": rfc3339Epoch(m.Timestamp), "Description": nil,
			})
		}
		v = map[string]any{"DescribeStackResourcesResponse": map[string]any{
			"DescribeStackResourcesResult": map[string]any{"StackResources": list},
			"ResponseMetadata":             meta(x.RequestID),
		}}
	default:
		return nil, false
	}
	out, err := json.Marshal(v)
	return out, err == nil
}

// rfc3339Epoch is an RFC 3339 timestamp as the Query protocol's JSON writes one (seconds since the epoch).
func rfc3339Epoch(ts string) float64 {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t = time.Now()
	}
	return float64(t.UnixMilli()) / 1000
}

// serveCFNV1 serves a call signed with an instance identity document.
func (h *cfnDoorway) serveCFNV1(w http.ResponseWriter, r *http.Request, requestID string) {
	// From the platform's own network only, as the identity documents are issued (internalonly.go): a
	// document copied out of a guest is no credential at the LAN Ingress.
	if refuseIfProxied(w, r) {
		return
	}
	_ = r.ParseForm()
	queryParamsAsForm(r)
	normalizeStackArgs(r)
	if strings.EqualFold(r.PostFormValue("ContentType"), "JSON") { // a refused action is answered in JSON too
		cw := newQueryCapture()
		h.serveInstanceCall(cw, r, requestID)
		cw.flushJSON(w)
		return
	}
	h.serveInstanceCall(w, r, requestID)
}

func (h *cfnDoorway) serveInstanceCall(w http.ResponseWriter, r *http.Request, requestID string) {
	ctx := r.Context()
	action := r.PostFormValue("Action")
	if !cfnJSONActions[action] {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			"an instance identity (CFN_V1) authorizes only SignalResource, DescribeStackResource and DescribeStackResources", cfnXMLNamespace)
		return
	}
	if h.identity == nil {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			"instance identity (CFN_V1) authentication is not enabled on this shim (IMDS_ENABLED)", cfnXMLNamespace)
		return
	}
	c, err := h.identity.verifyIdentity(ctx, r.Header.Get("Authorization"), h.account, h.region)
	if err != nil {
		h.logger.Warn("cloudformation: CFN_V1 call refused", "action", action, "reason", err.Error())
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, err.Error(), cfnXMLNamespace)
		return
	}
	stack := r.PostFormValue("StackName")
	if stack == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "StackName is required.", cfnXMLNamespace)
		return
	}
	denied := "instance " + c.InstanceID + " is not authorized to perform cloudformation:" + action + " on stack " + stack +
		": an instance identity reaches only the stack that launched the instance"
	rec, found, err := h.getRecord(ctx, stack)
	if err != nil {
		writeQueryError(w, http.StatusServiceUnavailable, "ServiceUnavailable", requestID, "the stack could not be read; retry", cfnXMLNamespace)
		return
	}
	if !found {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, denied, cfnXMLNamespace)
		return
	}
	if ok, reason := h.instanceInStack(r, rec, c.InstanceID); !ok {
		if reason != "" {
			denied += " (" + reason + ")"
		}
		h.logger.Warn("cloudformation: CFN_V1 call refused", "instance", c.InstanceID, "stack", stack, "action", action, "reason", reason)
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, denied, cfnXMLNamespace)
		return
	}
	h.logger.Info("cloudformation: CFN_V1 call", "instance", c.InstanceID, "stack", stack, "action", action)
	switch action {
	case "SignalResource":
		h.recordSignal(w, r, rec, requestID)
	case "DescribeStackResource":
		h.describeStackResourceOf(w, r, rec, nil, requestID)
	case "DescribeStackResources":
		h.describeStackResourcesOf(w, r, rec, nil, requestID)
	}
}

// instanceInStack reports whether the stack record lists the running VM whose instance id is id. reason
// explains a refusal that is the instance's own state (it is not running); "" when the stack does not have it.
func (h *cfnDoorway) instanceInStack(r *http.Request, rec *cfn.StackRecord, id string) (bool, string) {
	for _, res := range rec.Resources {
		if res.Kind != "VirtualMachine" || (res.APIVersion != "" && !strings.HasPrefix(res.APIVersion, "openinfra.dev/")) {
			continue
		}
		vm, err := readBoundVM(r.Context(), h.shimDyn, rec.Namespace, res.Name)
		if err != nil || vm.instanceID != id {
			continue
		}
		if !vmRunning(r.Context(), h.shimDyn, rec.Namespace, res.Name) {
			return false, "the instance is not running"
		}
		return true, ""
	}
	return false, ""
}
