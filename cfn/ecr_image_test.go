package cfn

import (
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// An image named as AWS names an account's private registry is that account's repository in the platform's
// registry: a member account's under its id, the management account's at the top; another region's, or one
// with no registry to serve it (the CLI), refuses; any other image is left as it is.
func TestECRImageRef(t *testing.T) {
	ctx := ecsCtx(t, "Resources: {}")
	ctx.caps.ECRRepositoryHost = "registry.example.test"
	region := ctx.region()
	mgmt := awsidentity.Current().AccountID
	for img, want := range map[string]string{
		"111122223333.dkr.ecr." + region + ".amazonaws.com/team/web:1":     "registry.example.test/111122223333/team/web:1",
		"111122223333.dkr.ecr." + region + ".amazonaws.com/web@sha256:abc": "registry.example.test/111122223333/web@sha256:abc",
		mgmt + ".dkr.ecr." + region + ".amazonaws.com/web:1":               "registry.example.test/web:1",
		"nginx:1.27-alpine":                        "nginx:1.27-alpine",
		"public.ecr.aws/nginx/nginx:1":             "public.ecr.aws/nginx/nginx:1",
		"registry.example.test/111122223333/web:1": "registry.example.test/111122223333/web:1",
	} {
		if got, why := ecrImageRef(img, ctx); why != "" || got != want {
			t.Errorf("%s -> %q (%s), want %q", img, got, why, want)
		}
	}
	if _, why := ecrImageRef("111122223333.dkr.ecr.eu-west-9.amazonaws.com/web:1", ctx); !strings.Contains(why, "eu-west-9") {
		t.Errorf("another region's ECR must refuse: %q", why)
	}
	ctx.caps.ECRRepositoryHost = ""
	if _, why := ecrImageRef("111122223333.dkr.ecr."+region+".amazonaws.com/web:1", ctx); why == "" {
		t.Error("an ECR image with no registry to serve it must refuse, never pull from AWS")
	}
}

// An ECS task's containers name their ECR images the AWS way and pull them from the platform's registry.
func TestTranslate_ECSService_ECRImages(t *testing.T) {
	tmpl := `
Resources:
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - { Name: web, Image: 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/web:1, PortMappings: [ { ContainerPort: 80 } ] }
        - { Name: log, Image: 111122223333.dkr.ecr.us-east-1.amazonaws.com/team/log:2 }
  Svc:
    Type: AWS::ECS::Service
    Properties: { TaskDefinition: !Ref Task }
`
	ctx := ecsCtx(t, tmpl)
	if ctx.region() != "us-east-1" {
		t.Skipf("the fixture names us-east-1; the stack region is %s", ctx.region())
	}
	ctx.caps.ECRRepositoryHost = "registry.example.test"
	m, fs := translateECSService("Svc", ecsResolvedService(t, ctx, "Svc"), ctx)
	if len(fs) != 0 {
		t.Fatal(findingsText(fs))
	}
	side := m.Spec["sidecars"].([]any)[0].(map[string]any)
	if m.Spec["image"] != "registry.example.test/111122223333/team/web:1" || side["image"] != "registry.example.test/111122223333/team/log:2" {
		t.Fatalf("images %v %v", m.Spec["image"], side["image"])
	}
}
