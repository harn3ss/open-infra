// A stack's secrets, log groups, EventBridge rules and buses, ECR repositories and alarms, provisioned
// through the shim front doors that serve those APIs (#347 M).
//
// These kinds take the same applier routing and ownership record as the queues, topics, parameters and
// keys of cfn_services.go (cfn.IsServiceKind; cfn_service_resources). What differs is how each step is
// carried out: not as a write to the store with the front door's checks repeated beside it, but as the
// API call itself, made in-process to that front door as the caller. The front door authenticates
// nothing (the caller already is) and authorizes exactly as for the same call made directly — its RBAC
// check, its data-plane policy, its escalation fences (an EventBridge target the caller could not invoke,
// an alarm action on a topic the caller could not publish to). Those fences live in the front doors, so
// calling them keeps one copy of each rule. A stack delete's pre-flight still checks each delete up front
// (doorAuthorizeDelete), so a teardown the caller cannot finish is refused before it starts.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// svcCtx is one caller acting in one stack namespace.
type svcCtx struct {
	s      *cfnServices
	claims iam.Claims
	ns     string
}

// svcError is a front door's refusal of an in-process call.
type svcError struct {
	Status        int
	Code, Message string
}

func (e *svcError) Error() string { return e.Code + ": " + e.Message }

// isCode reports whether err is a front-door refusal with one of codes.
func isCode(err error, codes ...string) bool {
	var se *svcError
	if !errors.As(err, &se) {
		return false
	}
	for _, c := range codes {
		if se.Code == c {
			return true
		}
	}
	return false
}

// svcTargetPrefix is each JSON-protocol front door's X-Amz-Target prefix.
var svcTargetPrefix = map[string]string{
	"secretsmanager": "secretsmanager.",
	"logs":           "Logs_20140328.",
	"events":         "AWSEvents.",
	"ecr":            "AmazonEC2ContainerRegistry_V20150921.",
	"monitoring":     "GraniteServiceVersion20100801.",
}

// call makes one API call to a front door in-process, as the caller.
func (c svcCtx) call(ctx context.Context, service, op string, body map[string]any) (map[string]any, error) {
	if c.s == nil || c.s.doors == nil {
		return nil, fmt.Errorf("the %s front door is not configured on this shim", service)
	}
	h, ok := c.s.doors[service]
	if !ok || h == nil {
		return nil, fmt.Errorf("the %s front door is not configured on this shim", service)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Amz-Target", svcTargetPrefix[service]+op)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	if service == "monitoring" {
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("x-amzn-query-mode", "true")
	}
	rec := httptest.NewRecorder()
	h.serve(rec, req, c.claims, "cfn-"+randomHex(8))
	if rec.Code >= 400 {
		var e struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		code := e.Type
		if i := strings.LastIndex(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		if rec.Code == http.StatusForbidden {
			return nil, cfn.Unauthorized(fmt.Sprintf("%s %s: %s: %s", service, op, code, e.Message))
		}
		return nil, &svcError{Status: rec.Code, Code: code, Message: e.Message}
	}
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// doorKind is how one front-door kind's resources are created, changed, read and removed — each step a
// call to that front door, as the caller.
type doorKind interface {
	exists(ctx context.Context, c svcCtx, name string, spec map[string]any) (bool, error)
	create(ctx context.Context, c svcCtx, name string, spec map[string]any) error
	update(ctx context.Context, c svcCtx, name string, spec, prev map[string]any) error
	remove(ctx context.Context, c svcCtx, name string, spec map[string]any) error
	// live is the resource's spec as its front door reports it, for drift: what it can read back, and the
	// recorded value of a write-only property (a secret's value, which AWS does not drift-check either).
	live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error)
	// deleteCheck is what a delete is authorized against: the RBAC resource and name, and the data-plane
	// action, resource type and id, as the front door checks them for the same delete.
	deleteCheck(name string, spec map[string]any) (rbacResource, rbacName, action, resType, resID string)
}

// doorRoute is a front-door kind and the front door (its services key) that serves it.
type doorRoute struct {
	service string
	doorKind
}

// doorKinds are the service kinds provisioned through their front doors (the others, cfn_services.go,
// are written to their stores directly).
var doorKinds = map[string]doorRoute{
	cfn.KindSecretsManagerSecret: {"secretsmanager", secretKind{}},
	cfn.KindLogsLogGroup:         {"logs", logGroupKind{}},
	cfn.KindEventsRule:           {"events", ruleKind{}},
	cfn.KindEventsEventBus:       {"events", eventBusKind{}},
	cfn.KindECRRepository:        {"ecr", repoKind{}},
	cfn.KindCloudWatchAlarm:      {"monitoring", alarmKind{}},
}

// --- shared helpers ---

func specStr(spec map[string]any, k string) string { s, _ := spec[k].(string); return s }

func specTags(spec map[string]any) map[string]string {
	out := map[string]string{}
	if m, ok := spec["tags"].(map[string]any); ok {
		for k, v := range m {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

// --- Secrets Manager secret ---

// cfnSecretARNKey carries, on an in-process CreateSecret, the ARN the stack's engine gave the secret (its
// Ref), so DescribeSecret reports the ARN the template sees. Only the CloudFormation front door sets it.
type cfnSecretARNKey struct{}

type secretKind struct{}

func (secretKind) exists(ctx context.Context, c svcCtx, name string, _ map[string]any) (bool, error) {
	_, err := c.call(ctx, "secretsmanager", "DescribeSecret", map[string]any{"SecretId": name})
	if isCode(err, "ResourceNotFoundException") {
		return false, nil
	}
	return err == nil, err
}

// secretValue is the value a new secret starts with: its SecretString, or one GenerateSecretString makes.
func secretValue(ctx context.Context, c svcCtx, spec map[string]any) (string, error) {
	if s, ok := spec["secretString"].(string); ok {
		return s, nil
	}
	gen, _ := spec["generateSecretString"].(map[string]any)
	req := map[string]any{}
	for k, v := range gen {
		if k != "SecretStringTemplate" && k != "GenerateStringKey" {
			req[k] = v
		}
	}
	out, err := c.call(ctx, "secretsmanager", "GetRandomPassword", req)
	if err != nil {
		return "", fmt.Errorf("generating the secret value: %w", err)
	}
	pw, _ := out["RandomPassword"].(string)
	tmpl, _ := gen["SecretStringTemplate"].(string)
	key, _ := gen["GenerateStringKey"].(string)
	if tmpl == "" || key == "" {
		return pw, nil
	}
	obj := map[string]any{}
	if err := json.Unmarshal([]byte(tmpl), &obj); err != nil {
		return "", fmt.Errorf("SecretStringTemplate is not a JSON object: %w", err)
	}
	obj[key] = pw
	b, _ := json.Marshal(obj)
	return string(b), nil
}

func (secretKind) create(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	v, err := secretValue(ctx, c, spec)
	if err != nil {
		return err
	}
	body := map[string]any{"Name": name, "SecretString": v}
	if d := specStr(spec, "description"); d != "" {
		body["Description"] = d
	}
	if t := specTags(spec); len(t) > 0 {
		body["Tags"] = tagList(t)
	}
	if arn := specStr(spec, "arn"); arn != "" {
		ctx = context.WithValue(ctx, cfnSecretARNKey{}, arn)
	}
	_, err = c.call(ctx, "secretsmanager", "CreateSecret", body)
	return err
}

func (secretKind) update(ctx context.Context, c svcCtx, name string, spec, prev map[string]any) error {
	if specStr(spec, "description") != specStr(prev, "description") || prev == nil {
		if _, err := c.call(ctx, "secretsmanager", "UpdateSecret", map[string]any{"SecretId": name, "Description": specStr(spec, "description")}); err != nil {
			return err
		}
	}
	// A new SecretString is a new version; a GenerateSecretString value is made once, at create (an update
	// that does not change the template's value writes nothing).
	if s, ok := spec["secretString"].(string); ok && (prev == nil || s != specStr(prev, "secretString")) {
		if _, err := c.call(ctx, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": name, "SecretString": s}); err != nil {
			return err
		}
	}
	return syncTags(ctx, c, "secretsmanager", map[string]any{"SecretId": name}, specTags(spec), specTags(prev))
}

// syncTags tags and untags a secret toward want (from had, the tags last applied).
func syncTags(ctx context.Context, c svcCtx, service string, id map[string]any, want, had map[string]string) error {
	var gone []any
	for k := range had {
		if _, keep := want[k]; !keep {
			gone = append(gone, k)
		}
	}
	if len(gone) > 0 {
		body := map[string]any{"TagKeys": gone}
		for k, v := range id {
			body[k] = v
		}
		if _, err := c.call(ctx, service, "UntagResource", body); err != nil {
			return err
		}
	}
	if len(want) > 0 {
		body := map[string]any{"Tags": tagList(want)}
		for k, v := range id {
			body[k] = v
		}
		if _, err := c.call(ctx, service, "TagResource", body); err != nil {
			return err
		}
	}
	return nil
}

func (secretKind) remove(ctx context.Context, c svcCtx, name string, _ map[string]any) error {
	// As a stack delete on AWS: removed at once, with no recovery window.
	_, err := c.call(ctx, "secretsmanager", "DeleteSecret", map[string]any{"SecretId": name, "ForceDeleteWithoutRecovery": true})
	if isCode(err, "ResourceNotFoundException") {
		return nil
	}
	return err
}

func (secretKind) live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	out, err := c.call(ctx, "secretsmanager", "DescribeSecret", map[string]any{"SecretId": name})
	if err != nil {
		return nil, err
	}
	l := map[string]any{"name": out["Name"], "arn": out["ARN"]}
	if d, _ := out["Description"].(string); d != "" {
		l["description"] = d
	}
	for _, k := range []string{"secretString", "generateSecretString"} { // write-only: not drift-checked
		if v, ok := recorded[k]; ok {
			l[k] = v
		}
	}
	if tl, ok := out["Tags"].([]any); ok && len(tl) > 0 {
		t := map[string]any{}
		for _, e := range tl {
			m, _ := e.(map[string]any)
			t[fmt.Sprint(m["Key"])] = fmt.Sprint(m["Value"])
		}
		l["tags"] = t
	}
	return l, nil
}

func (secretKind) deleteCheck(name string, _ map[string]any) (string, string, string, string, string) {
	return "secrets", name, "secretsmanager:DeleteSecret", "Secret", name
}

// --- CloudWatch Logs log group ---

type logGroupKind struct{}

func (logGroupKind) find(ctx context.Context, c svcCtx, name string) (map[string]any, error) {
	out, err := c.call(ctx, "logs", "DescribeLogGroups", map[string]any{"logGroupNamePrefix": name})
	if err != nil {
		return nil, err
	}
	gs, _ := out["logGroups"].([]any)
	for _, g := range gs {
		if m, _ := g.(map[string]any); m["logGroupName"] == name {
			return m, nil
		}
	}
	return nil, nil
}

func (k logGroupKind) exists(ctx context.Context, c svcCtx, name string, _ map[string]any) (bool, error) {
	g, err := k.find(ctx, c, name)
	return g != nil, err
}

func (logGroupKind) setRetention(ctx context.Context, c svcCtx, name string, spec map[string]any, had bool) error {
	if d, ok := spec["retentionInDays"]; ok {
		_, err := c.call(ctx, "logs", "PutRetentionPolicy", map[string]any{"logGroupName": name, "retentionInDays": d})
		return err
	}
	if had {
		_, err := c.call(ctx, "logs", "DeleteRetentionPolicy", map[string]any{"logGroupName": name})
		return err
	}
	return nil
}

func (k logGroupKind) create(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	body := map[string]any{"logGroupName": name}
	if t := specTags(spec); len(t) > 0 {
		body["tags"] = t
	}
	if _, err := c.call(ctx, "logs", "CreateLogGroup", body); err != nil {
		return err
	}
	return k.setRetention(ctx, c, name, spec, false)
}

func (k logGroupKind) update(ctx context.Context, c svcCtx, name string, spec, prev map[string]any) error {
	_, had := prev["retentionInDays"]
	if err := k.setRetention(ctx, c, name, spec, had || prev == nil); err != nil {
		return err
	}
	if t := specTags(spec); len(t) > 0 {
		if _, err := c.call(ctx, "logs", "TagLogGroup", map[string]any{"logGroupName": name, "tags": t}); err != nil {
			return err
		}
	}
	return nil
}

func (logGroupKind) remove(ctx context.Context, c svcCtx, name string, _ map[string]any) error {
	_, err := c.call(ctx, "logs", "DeleteLogGroup", map[string]any{"logGroupName": name})
	if isCode(err, "ResourceNotFoundException") {
		return nil
	}
	return err
}

func (k logGroupKind) live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	g, err := k.find(ctx, c, name)
	if err != nil || g == nil {
		return nil, err
	}
	l := map[string]any{"name": name}
	if d, ok := g["retentionInDays"]; ok {
		l["retentionInDays"] = d
	}
	for _, p := range []string{"logGroupClass", "fieldIndexPolicies", "tags"} { // not read back by the front door
		if v, ok := recorded[p]; ok {
			l[p] = v
		}
	}
	return l, nil
}

func (logGroupKind) deleteCheck(name string, _ map[string]any) (string, string, string, string, string) {
	return "applications", name, "logs:DeleteLogGroup", "LogGroup", name
}

// --- EventBridge rule ---

// cfnTargetNamespaceKey carries, on an in-process PutTargets, the namespace each in-stack Function target
// runs in (target id -> namespace): a stack's Functions are in its own namespace, not the Lambda front
// door's. Only the CloudFormation front door sets it, and the target is authorized in that namespace.
type cfnTargetNamespaceKey struct{}

type ruleKind struct{}

func busOfSpec(spec map[string]any) string {
	if b := specStr(spec, "eventBusName"); b != "" {
		return b
	}
	return "default"
}

func (ruleKind) exists(ctx context.Context, c svcCtx, name string, spec map[string]any) (bool, error) {
	_, err := c.call(ctx, "events", "DescribeRule", map[string]any{"Name": name, "EventBusName": busOfSpec(spec)})
	if isCode(err, "ResourceNotFoundException") {
		return false, nil
	}
	return err == nil, err
}

func (k ruleKind) put(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	body := map[string]any{"Name": name, "EventBusName": busOfSpec(spec), "State": specStr(spec, "state"),
		"Description": specStr(spec, "description")}
	if s := specStr(spec, "scheduleExpression"); s != "" {
		body["ScheduleExpression"] = s
	}
	if p := specStr(spec, "eventPattern"); p != "" {
		body["EventPattern"] = p
	}
	if _, err := c.call(ctx, "events", "PutRule", body); err != nil {
		return err
	}
	return k.syncTargets(ctx, c, name, spec)
}

// syncTargets makes the rule's targets exactly the spec's.
func (ruleKind) syncTargets(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	bus := busOfSpec(spec)
	out, err := c.call(ctx, "events", "ListTargetsByRule", map[string]any{"Rule": name, "EventBusName": bus})
	if err != nil {
		return err
	}
	want := map[string]bool{}
	var targets []any
	nsByID := map[string]string{}
	tl, _ := spec["targets"].([]any)
	for _, t := range tl {
		m, _ := t.(map[string]any)
		id := specStr(m, "id")
		want[id] = true
		arn := specStr(m, "arn")
		if fn := specStr(m, "function"); fn != "" {
			arn = "arn:aws:lambda:::function:" + fn
			nsByID[id] = c.ns
		}
		tb := map[string]any{"Id": id, "Arn": arn}
		if in, ok := m["input"].(string); ok {
			tb["Input"] = in
		}
		targets = append(targets, tb)
	}
	var stale []any
	have, _ := out["Targets"].([]any)
	for _, t := range have {
		m, _ := t.(map[string]any)
		if id := specStr(m, "Id"); !want[id] {
			stale = append(stale, id)
		}
	}
	if len(stale) > 0 {
		if _, err := c.call(ctx, "events", "RemoveTargets", map[string]any{"Rule": name, "EventBusName": bus, "Ids": stale}); err != nil {
			return err
		}
	}
	if len(targets) > 0 {
		tctx := context.WithValue(ctx, cfnTargetNamespaceKey{}, nsByID)
		if _, err := c.call(tctx, "events", "PutTargets", map[string]any{"Rule": name, "EventBusName": bus, "Targets": targets}); err != nil {
			return err
		}
	}
	return nil
}

func (k ruleKind) create(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	return k.put(ctx, c, name, spec)
}

func (k ruleKind) update(ctx context.Context, c svcCtx, name string, spec, _ map[string]any) error {
	return k.put(ctx, c, name, spec)
}

func (ruleKind) remove(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	bus := busOfSpec(spec)
	out, err := c.call(ctx, "events", "ListTargetsByRule", map[string]any{"Rule": name, "EventBusName": bus})
	if isCode(err, "ResourceNotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	var ids []any
	have, _ := out["Targets"].([]any)
	for _, t := range have {
		m, _ := t.(map[string]any)
		ids = append(ids, specStr(m, "Id"))
	}
	if len(ids) > 0 { // a rule with targets cannot be deleted (as on AWS)
		if _, err := c.call(ctx, "events", "RemoveTargets", map[string]any{"Rule": name, "EventBusName": bus, "Ids": ids}); err != nil {
			return err
		}
	}
	_, err = c.call(ctx, "events", "DeleteRule", map[string]any{"Name": name, "EventBusName": bus})
	if isCode(err, "ResourceNotFoundException") {
		return nil
	}
	return err
}

func (ruleKind) live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	out, err := c.call(ctx, "events", "DescribeRule", map[string]any{"Name": name, "EventBusName": busOfSpec(recorded)})
	if err != nil {
		return nil, err
	}
	l := map[string]any{"name": name, "eventBusName": busOfSpec(recorded), "state": out["State"]}
	if d, _ := out["Description"].(string); d != "" {
		l["description"] = d
	}
	for _, p := range []string{"scheduleExpression", "eventPattern", "targets", "tags"} {
		if v, ok := recorded[p]; ok {
			l[p] = v
		}
	}
	return l, nil
}

func (ruleKind) deleteCheck(name string, spec map[string]any) (string, string, string, string, string) {
	id := ruleResourceID(busOfSpec(spec), name) // as the EventBridge front door authorizes DeleteRule
	return "applications", id, "events:DeleteRule", "Rule", id
}

// --- EventBridge event bus ---

type eventBusKind struct{}

func (eventBusKind) find(ctx context.Context, c svcCtx, name string) (map[string]any, error) {
	out, err := c.call(ctx, "events", "ListEventBuses", map[string]any{"NamePrefix": name})
	if err != nil {
		return nil, err
	}
	bs, _ := out["EventBuses"].([]any)
	for _, b := range bs {
		if m, _ := b.(map[string]any); m["Name"] == name {
			return m, nil
		}
	}
	return nil, nil
}

func (k eventBusKind) exists(ctx context.Context, c svcCtx, name string, _ map[string]any) (bool, error) {
	b, err := k.find(ctx, c, name)
	return b != nil, err
}

func (eventBusKind) create(ctx context.Context, c svcCtx, name string, _ map[string]any) error {
	_, err := c.call(ctx, "events", "CreateEventBus", map[string]any{"Name": name})
	return err
}

func (eventBusKind) update(context.Context, svcCtx, string, map[string]any, map[string]any) error {
	return nil // a bus has nothing to change but its name, which is its identity
}

func (eventBusKind) remove(ctx context.Context, c svcCtx, name string, _ map[string]any) error {
	_, err := c.call(ctx, "events", "DeleteEventBus", map[string]any{"Name": name})
	if isCode(err, "ResourceNotFoundException") {
		return nil
	}
	return err
}

func (eventBusKind) live(_ context.Context, _ svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	l := map[string]any{"name": name}
	for _, p := range []string{"description", "tags"} {
		if v, ok := recorded[p]; ok {
			l[p] = v
		}
	}
	return l, nil
}

func (eventBusKind) deleteCheck(name string, _ map[string]any) (string, string, string, string, string) {
	return "applications", name, "events:DeleteEventBus", "EventBus", name
}

// --- ECR repository ---

type repoKind struct{}

func (repoKind) find(ctx context.Context, c svcCtx, name string) (map[string]any, error) {
	out, err := c.call(ctx, "ecr", "DescribeRepositories", map[string]any{"repositoryNames": []any{name}})
	if isCode(err, "RepositoryNotFoundException") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rs, _ := out["repositories"].([]any)
	if len(rs) == 0 {
		return nil, nil
	}
	m, _ := rs[0].(map[string]any)
	return m, nil
}

func (k repoKind) exists(ctx context.Context, c svcCtx, name string, _ map[string]any) (bool, error) {
	r, err := k.find(ctx, c, name)
	return r != nil, err
}

func (repoKind) create(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	_, err := c.call(ctx, "ecr", "CreateRepository", map[string]any{"repositoryName": name, "imageTagMutability": specStr(spec, "imageTagMutability")})
	return err
}

func (k repoKind) update(ctx context.Context, c svcCtx, name string, spec, _ map[string]any) error {
	r, err := k.find(ctx, c, name)
	if err != nil {
		return err
	}
	if want := specStr(spec, "imageTagMutability"); r != nil && want != "" && r["imageTagMutability"] != want {
		_, err = c.call(ctx, "ecr", "PutImageTagMutability", map[string]any{"repositoryName": name, "imageTagMutability": want})
	}
	return err
}

func (repoKind) remove(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	// EmptyOnDelete: a repository that still holds images is deleted with them; otherwise its delete fails
	// (RepositoryNotEmptyException) and so does the stack's, as on AWS.
	force, _ := spec["emptyOnDelete"].(bool)
	_, err := c.call(ctx, "ecr", "DeleteRepository", map[string]any{"repositoryName": name, "force": force})
	if isCode(err, "RepositoryNotFoundException") {
		return nil
	}
	return err
}

func (k repoKind) live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	r, err := k.find(ctx, c, name)
	if err != nil || r == nil {
		return nil, err
	}
	l := map[string]any{"name": name, "imageTagMutability": r["imageTagMutability"]}
	for _, p := range []string{"emptyOnDelete", "scanOnPush", "lifecyclePolicy", "repositoryPolicy", "encryption", "tags"} {
		if v, ok := recorded[p]; ok {
			l[p] = v
		}
	}
	return l, nil
}

func (repoKind) deleteCheck(name string, _ map[string]any) (string, string, string, string, string) {
	return "repositories", name, "ecr:DeleteRepository", "Repository", name
}

// --- CloudWatch alarm ---

type alarmKind struct{}

func (alarmKind) find(ctx context.Context, c svcCtx, name string) (map[string]any, error) {
	out, err := c.call(ctx, "monitoring", "DescribeAlarms", map[string]any{"AlarmNames": []any{name}})
	if err != nil {
		return nil, err
	}
	as, _ := out["MetricAlarms"].([]any)
	for _, a := range as {
		if m, _ := a.(map[string]any); m["AlarmName"] == name {
			return m, nil
		}
	}
	return nil, nil
}

func (k alarmKind) exists(ctx context.Context, c svcCtx, name string, _ map[string]any) (bool, error) {
	a, err := k.find(ctx, c, name)
	return a != nil, err
}

func (alarmKind) put(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	body := map[string]any{"AlarmName": name}
	for k, p := range map[string]string{"namespace": "Namespace", "metricName": "MetricName", "statistic": "Statistic",
		"extendedStatistic": "ExtendedStatistic", "comparisonOperator": "ComparisonOperator", "treatMissingData": "TreatMissingData",
		"threshold": "Threshold", "period": "Period", "evaluationPeriods": "EvaluationPeriods", "datapointsToAlarm": "DatapointsToAlarm",
		"description": "AlarmDescription", "unit": "Unit"} {
		if v, ok := spec[k]; ok && fmt.Sprint(v) != "" {
			body[p] = v
		}
	}
	if d, ok := spec["dimensions"].([]any); ok {
		body["Dimensions"] = d
	}
	if a, ok := spec["alarmActions"].([]any); ok {
		body["AlarmActions"] = a
	}
	_, err := c.call(ctx, "monitoring", "PutMetricAlarm", body)
	return err
}

func (k alarmKind) create(ctx context.Context, c svcCtx, name string, spec map[string]any) error {
	return k.put(ctx, c, name, spec)
}

func (k alarmKind) update(ctx context.Context, c svcCtx, name string, spec, _ map[string]any) error {
	return k.put(ctx, c, name, spec)
}

func (alarmKind) remove(ctx context.Context, c svcCtx, name string, _ map[string]any) error {
	_, err := c.call(ctx, "monitoring", "DeleteAlarms", map[string]any{"AlarmNames": []any{name}})
	if isCode(err, "ResourceNotFound") {
		return nil
	}
	return err
}

func (k alarmKind) live(ctx context.Context, c svcCtx, name string, recorded map[string]any) (map[string]any, error) {
	a, err := k.find(ctx, c, name)
	if err != nil || a == nil {
		return nil, err
	}
	l := map[string]any{}
	for kk, v := range recorded { // the front door reports the alarm as it was put; read back what it names
		l[kk] = v
	}
	l["name"] = name
	if v, ok := a["Threshold"]; ok {
		l["threshold"] = fmt.Sprint(v)
	}
	if v, ok := a["ComparisonOperator"]; ok {
		l["comparisonOperator"] = v
	}
	return l, nil
}

func (alarmKind) deleteCheck(name string, spec map[string]any) (string, string, string, string, string) {
	ns := specStr(spec, "namespace")
	return "applications", ns, "cloudwatch:DeleteAlarms", "Namespace", ns
}

// --- the routing main's dispatch (cfn_services.go) hands these kinds to ---

// doorOK reports whether service's front door is served here with its store, so a stack may provision
// its kinds (the doorway vouches for it in caps(); the engine refuses the type otherwise).
func (s *cfnServices) doorOK(service string) bool {
	if s == nil || s.owners == nil || s.doors == nil {
		return false
	}
	switch h := s.doors[service].(type) {
	case nil:
		return false
	case *secretsHandler:
		return h != nil && h.store != nil && h.transit != nil
	case *cwlHandler:
		return h != nil && h.store != nil
	case *ebHandler:
		return h != nil && h.store != nil
	case *cwHandler:
		return h != nil && h.store != nil
	case *ecrHandler:
		return h != nil
	}
	return true // a front door with no separate store
}

// svcCtx is the caller acting in stack namespace ns.
func (a *impersonatingApplier) svcCtx(ns string) svcCtx {
	if ns == "" {
		ns = a.ns
	}
	return svcCtx{s: a.svc, claims: a.callerClaims(), ns: ns}
}

// doorExists reports whether a front-door kind's resource exists. spec locates it (a rule's bus); nil =
// the spec its stack recorded.
func (a *impersonatingApplier) doorExists(ctx context.Context, dk doorRoute, kind, name string, spec map[string]any) (bool, error) {
	if spec == nil {
		_, rec, _, err := a.svc.owners.get(ctx, kind, name)
		if err != nil {
			return false, err
		}
		spec = rec
	}
	return dk.exists(ctx, a.svcCtx(""), name, spec)
}

// doorAuthorizeDelete is a front-door kind's delete check, made as that front door makes it for the same
// delete (its RBAC resource and data-plane action): the pre-flight of a stack delete.
func (a *impersonatingApplier) doorAuthorizeDelete(ctx context.Context, dk doorRoute, kind, name string, spec map[string]any) error {
	res, rname, action, resType, resID := dk.deleteCheck(name, spec)
	if ok, reason := a.door.callerCan(ctx, a, "delete", "openinfra.dev", res, a.door.authzNS, rname); !ok {
		return cfn.Unauthorized(fmt.Sprintf("%s %s not deleted: %s", kind, name, reason))
	}
	if ok, reason := a.door.callerPolicyAllows(ctx, a, action, resType, resID); !ok {
		return cfn.Unauthorized(fmt.Sprintf("%s %s not deleted: %s", kind, name, reason))
	}
	return nil
}
