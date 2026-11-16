package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// A member account's stack, created by executing a change set, names its own account in its resources'
// physical ids (a task definition's ARN), as the stack's own resolution does: never the management account's.
func TestCFNAccounts_MemberChangeSetStackNamesItsAccount(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim/0001")
	h.noecho = &noEchoSecrets{cs: k8sfake.NewSimpleClientset(), ns: shimNS}
	h.authz = doorAccountsAuthz(t)
	tmpl := `
Resources:
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: web
      ContainerDefinitions: [{ Name: web, Image: nginx, PortMappings: [{ ContainerPort: 80 }] }]
  Service:
    Type: AWS::ECS::Service
    Properties: { ServiceName: web, TaskDefinition: !Ref Task, DesiredCount: 1 }
`
	code, body := memberCFNCall(t, h, url.Values{"Action": {"CreateChangeSet"}, "StackName": {"web"}, "ChangeSetName": {"cs1"},
		"ChangeSetType": {"CREATE"}, "TemplateBody": {tmpl}})
	if code != 200 {
		t.Fatalf("CreateChangeSet: %d %s", code, body)
	}
	code, body = memberCFNCall(t, h, url.Values{"Action": {"ExecuteChangeSet"}, "StackName": {"web"}, "ChangeSetName": {"cs1"}})
	if code != 200 {
		t.Fatalf("ExecuteChangeSet: %d %s", code, body)
	}
	h.ops.drain(20 * time.Second)
	_, body = memberCFNCall(t, h, url.Values{"Action": {"DescribeStackResources"}, "StackName": {"web"}})
	if !strings.Contains(body, "task-definition/web:1") {
		t.Fatalf("DescribeStackResources lists no task definition: %s", body)
	}
	if strings.Contains(body, ":000000000000:") || !strings.Contains(body, ":"+testMember+":task-definition/web:1") {
		t.Fatalf("the member account's stack names another account: %s", body)
	}
}
