package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
)

// awsManagedPolicies maps the AWS managed policies an EC2 instance role commonly attaches to the part of
// each that open-infra's front doors serve, as the policy document the importer turns into a companion
// kind: Policy (spec.dataPlane) of the role — the same path inline Policies take. The rest of a managed
// policy names services open-infra does not run; it is listed in that policy's caveat, never granted.
var awsManagedPolicies = map[string]struct {
	doc, missing string
}{
	"AmazonEC2ContainerRegistryReadOnly": {
		doc:     `{"Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:DescribeRepositories","ecr:ListImages","ecr:DescribeImages","ecr:BatchGetImage"],"Resource":"*"}]}`,
		missing: "repository policies, lifecycle policies, scan findings and tags (the registry has none to read)",
	},
	"AmazonEC2ContainerRegistryPullOnly": {
		doc:     `{"Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":"*"}]}`,
		missing: "ecr:BatchImportUpstreamImage (pull-through cache rules are not served)",
	},
	"AmazonS3ReadOnlyAccess": {
		doc:     `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]}`,
		missing: "S3 Object Lambda (not served)",
	},
	"AmazonSSMManagedInstanceCore": {
		doc:     `{"Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"*"}]}`,
		missing: "Session Manager, Run Command, inventory, patching and the rest of the SSM agent's channel (ssm agent APIs, ssmmessages, ec2messages) — there is no SSM agent endpoint; only the policy's parameter reads are attached",
	},
	"CloudWatchAgentServerPolicy": {
		doc:     `{"Statement":[{"Effect":"Allow","Action":["cloudwatch:PutMetricData","logs:PutLogEvents","logs:PutRetentionPolicy","logs:DescribeLogStreams","logs:DescribeLogGroups","logs:CreateLogStream","logs:CreateLogGroup"],"Resource":"*"},{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":"arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"}]}`,
		missing: "ec2:DescribeVolumes/DescribeTags and X-Ray (not served)",
	},
}

// managedPolicyCompanions turns a role's ManagedPolicyArns into companion kind: Policy objects for the
// managed policies awsManagedPolicies maps, with a caveat naming what of each is not attached. An ARN it
// does not map (a customer managed policy, another AWS one) is a caveat: nothing is attached for it.
func managedPolicyCompanions(id, roleName string, v any) ([]*Manifest, []string, []Finding) {
	arns, f := stringList(id, "ManagedPolicyArns", v)
	var out []*Manifest
	var caveats, unmapped []string
	for _, arn := range arns {
		name := arn
		if i := strings.Index(arn, ":policy/"); i >= 0 && strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":iam::aws:policy/") {
			name = arn[i+len(":policy/"):]
			if j := strings.LastIndex(name, "/"); j >= 0 {
				name = name[j+1:]
			}
		}
		mp, ok := awsManagedPolicies[name]
		if !ok || !strings.Contains(arn, ":iam::aws:policy/") {
			unmapped = append(unmapped, arn)
			continue
		}
		stmts, unsupported, err := policyengine.ImportAWS(mp.doc)
		if err != nil || len(unsupported) > 0 || len(stmts) == 0 {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("managed policy %s did not import (%v %v) — this is an engine bug", name, err, unsupported)})
			continue
		}
		pname := companionPolicyName(roleName, "managed-"+k8sName(name))
		out = append(out, &Manifest{
			APIVersion: "iam.openinfra.dev/v1", Kind: "Policy", Name: pname,
			Spec: map[string]any{"dataPlane": map[string]any{
				"appliesTo":  []any{"Role::" + roleName},
				"statements": statementsToSpec(stmts),
			}},
		})
		caveats = append(caveats, fmt.Sprintf("managed policy %s is attached as kind: Policy %s with the access open-infra serves; not attached: %s", name, pname, mp.missing))
	}
	if len(unmapped) > 0 {
		caveats = append(caveats, "ManagedPolicyArns "+strings.Join(unmapped, ", ")+" are NOT attached — open-infra attaches AmazonEC2ContainerRegistryReadOnly, AmazonEC2ContainerRegistryPullOnly, AmazonS3ReadOnlyAccess, AmazonSSMManagedInstanceCore and CloudWatchAgentServerPolicy (the parts its services serve); express other access as inline Policies, or a kind: Policy in spec.policies")
	}
	return out, caveats, f
}

// maxCompanionNameLen is the longest name a role's companion kind: Policy gets: a Kubernetes label value
// (the policy's name is carried in labels), which is also the RFC 1123 label limit.
const maxCompanionNameLen = 63

// companionPolicyName is <role>-<suffix>, the name of a companion kind: Policy of a role (an inline or a
// managed policy). One that does not fit maxCompanionNameLen is shortened with a hash of the full name
// appended, so it stays unique per (role, suffix): a long stack name or policy name never fails the
// deploy on a too-long name.
func companionPolicyName(roleName, suffix string) string {
	n := roleName + "-" + suffix // unchanged for every name that fits, so no deployed policy is renamed
	if len(n) <= maxCompanionNameLen {
		return n
	}
	sum := sha256.Sum256([]byte(roleName + "\x00" + suffix))
	head := strings.Trim(n[:maxCompanionNameLen-9], "-")
	return head + "-" + hex.EncodeToString(sum[:])[:8]
}
