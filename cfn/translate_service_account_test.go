package cfn

import (
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// An ECR repository's RepositoryUri is in its stack's account's registry: the registry's root for the
// management account's stack (as before accounts), the "<account>/" path for a member account's — where
// the aws-shim's ECR door keeps that account's repositories — and its Arn names the stack's account.
func TestServiceStatic_ECRRepositoryIsInTheStacksAccountsRegistry(t *testing.T) {
	defer awsidentity.Set(awsidentity.Current())
	install := awsidentity.Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	awsidentity.Set(install)
	member := install.ForAccount("912345678901", "team-a")
	tpl := []byte(`
Resources:
  Repo: { Type: AWS::ECR::Repository, Properties: { RepositoryName: web } }
`)
	for _, tc := range []struct{ stackID, uri, arn string }{
		{install.NewStackID("app"), "registry.site/web", "arn:aws:ecr:eu-west-1:123456789012:repository/web"},
		{member.NewStackID("app"), "registry.site/912345678901/web", "arn:aws:ecr:eu-west-1:912345678901:repository/web"},
	} {
		tmpl, err := Parse(tpl)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &stackCtx{template: tmpl, resolver: newResolver(tmpl, nil, nil, pseudoParamsFor("app", tc.stackID)), caps: serviceCaps}
		if got, ok := serviceStatic("Repo", "RepositoryUri", ctx); !ok || got != tc.uri {
			t.Errorf("RepositoryUri in %s = %q, want %q", tc.stackID, got, tc.uri)
		}
		if got, ok := serviceStatic("Repo", "Arn", ctx); !ok || got != tc.arn {
			t.Errorf("Arn in %s = %q, want %q", tc.stackID, got, tc.arn)
		}
	}
}
