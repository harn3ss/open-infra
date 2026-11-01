package cfn

import (
	"context"
	"strings"
	"testing"
	"time"
)

const noEchoTmpl = `
Parameters:
  DbPassword: { Type: String, NoEcho: true }
  ApiToken:   { Type: String, NoEcho: "true" }
  Env:        { Type: String, Default: dev }
Resources:
  Logs:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: logs
      AttributeDefinitions: [{ AttributeName: id, AttributeType: S }]
      KeySchema: [{ AttributeName: id, KeyType: HASH }]
`

func TestParse_NoEcho_BoolOrString(t *testing.T) {
	tm := mustParse(t, []byte(noEchoTmpl))
	if !tm.Parameters["DbPassword"].NoEcho || !tm.Parameters["ApiToken"].NoEcho {
		t.Fatalf("NoEcho true and \"true\" must both parse: %+v", tm.Parameters)
	}
	if tm.Parameters["Env"].NoEcho {
		t.Fatal("a parameter without NoEcho must not be NoEcho")
	}
}

// noEchoApplier records the stack-record ConfigMap bytes and what it was asked to store as NoEcho.
type noEchoApplier struct {
	fakeApplier
	recordYAML []string
	stored     map[string]string
	puts       int
}

func (n *noEchoApplier) Apply(ctx context.Context, y []byte) error {
	if strings.HasPrefix(idOf(y), "ConfigMap/cfn-stack-") {
		n.recordYAML = append(n.recordYAML, string(y))
	}
	return n.fakeApplier.Apply(ctx, y)
}

func (n *noEchoApplier) PutNoEcho(_ context.Context, _ string, values map[string]string) error {
	n.puts++
	n.stored = values
	return nil
}

// A NoEcho value never reaches the stack record: the record names the parameter, the value goes to the
// Applier's NoEchoStore. Plain parameters stay in the record (UsePreviousValue reads them there).
func TestDeploy_NoEchoValuesStayOutOfTheRecord(t *testing.T) {
	ap := &noEchoApplier{}
	opts := DeployOptions{StackName: "s", Namespace: "cfn-test", Wait: true, Timeout: time.Second,
		Params: map[string]string{"DbPassword": "hunter2-secret", "ApiToken": "tok-secret", "Env": "prod"}}
	rec, err := Deploy(context.Background(), []byte(noEchoTmpl), opts, ap)
	if err != nil {
		t.Fatal(err)
	}
	for _, y := range ap.recordYAML {
		if strings.Contains(y, "hunter2-secret") || strings.Contains(y, "tok-secret") {
			t.Fatalf("a NoEcho value was written into the stack record:\n%s", y)
		}
	}
	if len(ap.recordYAML) == 0 || !strings.Contains(ap.recordYAML[0], "prod") {
		t.Fatalf("the plain parameter must stay in the record: %v", ap.recordYAML)
	}
	if ap.stored["DbPassword"] != "hunter2-secret" || ap.stored["ApiToken"] != "tok-secret" || ap.stored["Env"] != "" {
		t.Fatalf("NoEchoStore got %v, want only the two NoEcho values", ap.stored)
	}
	if got := strings.Join(rec.NoEchoParameters, ","); got != "ApiToken,DbPassword" {
		t.Fatalf("NoEchoParameters = %q", got)
	}
	// A record read back and re-written (a status change) leaves the store alone.
	before := ap.puts
	back := ap.fakeApplier.stored
	back.Status = "UPDATE_ROLLBACK_COMPLETE"
	if err := writeStackRecord(context.Background(), ap, back, opts); err != nil {
		t.Fatal(err)
	}
	if ap.puts != before {
		t.Fatal("re-writing a record read back must not touch the NoEcho store")
	}
}

// Without a NoEchoStore the values are dropped, never written in plain text.
func TestDeploy_NoEchoWithoutStoreIsNotKept(t *testing.T) {
	ap := &fakeApplier{}
	opts := DeployOptions{StackName: "s", Namespace: "cfn-test", Wait: true, Timeout: time.Second,
		Params: map[string]string{"DbPassword": "hunter2-secret", "ApiToken": "tok-secret"}}
	if _, err := Deploy(context.Background(), []byte(noEchoTmpl), opts, ap); err != nil {
		t.Fatal(err)
	}
	if v, ok := ap.stored.Parameters["DbPassword"]; ok {
		t.Fatalf("NoEcho value kept in the record without a store: %q", v)
	}
	if len(ap.stored.NoEchoParameters) != 2 {
		t.Fatalf("the record must still name the NoEcho parameters: %v", ap.stored.NoEchoParameters)
	}
}

func TestSplitNoEcho_UnparsableTemplateHidesEverything(t *testing.T) {
	plain, names, secret := SplitNoEcho([]byte("{not a template"), map[string]string{"A": "1"})
	if plain != nil || len(names) != 1 || secret["A"] != "1" {
		t.Fatalf("plain=%v names=%v secret=%v", plain, names, secret)
	}
}
